using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal sealed class LookupRow
{
    internal readonly string[] Values;
    internal bool HasMatch { get { return Values[1].Length > 0 && Values[2].Length > 0; } }
    internal readonly bool IsIssue;
    internal readonly bool CanRetry;

    internal LookupRow(string query, string address, string name, string status, string verification = "", bool canRetry = false, bool invalid = false)
    {
        Values = new[] { query, address, name, status, verification };
        IsIssue = canRetry || invalid;
        CanRetry = canRetry;
    }
}

internal sealed class DnsLookup
{
    private const ushort A = 1, Ptr = 12, Aaaa = 28;
    private const ulong DnsOnly = 0x40 | 0x80 | 0x800; // Skip hosts file, NetBIOS and multicast.
    private const ulong WireOnly = 0x100;
    private const int FreeRecordList = 1;
    private const int NameError = 9003, NoRecords = 9501, Pending = 9506, Timeout = 1460;
    private const int NativeCancelSize = 32;
    private const int ServerArrayHeaderSize = 32, ServerAddressSize = 64;
    private static readonly int DataOffset = Marshal.OffsetOf(typeof(DnsRecord), "Data").ToInt32();
    private static readonly NativeCompletion Complete = SignalCompletion;
    private readonly IPAddress server;
    private readonly int timeoutMs;

    internal DnsLookup(IPAddress server, int timeoutMs)
    {
        this.server = server;
        this.timeoutMs = timeoutMs;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsRecord
    {
        public IntPtr Next;
        public IntPtr Name;
        public ushort Type;
        public ushort DataLength;
        public uint Flags;
        public uint Ttl;
        public uint Reserved;
        public IntPtr Data; // Beginning of the native record data union.
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRequest
    {
        public uint Version;
        public IntPtr Name;
        public ushort Type;
        public ulong Options;
        public IntPtr Servers;
        public uint InterfaceIndex;
        public IntPtr Completion;
        public IntPtr Context;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeResult
    {
        public uint Version;
        public int Status;
        public ulong Options;
        public IntPtr Records;
        public IntPtr Reserved;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void NativeCompletion(IntPtr context, IntPtr result);

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern int DnsQueryEx(ref NativeRequest request, IntPtr results, IntPtr cancel);

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern int DnsCancelQuery(IntPtr cancel);

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern void DnsFree(IntPtr data, int freeType);

    internal static bool TryAddress(string input, out IPAddress ip)
    {
        return IPAddress.TryParse(input, out ip) &&
            (ip.AddressFamily == AddressFamily.InterNetworkV6 || ip.ToString() == input);
    }

    internal static IPAddress CanonicalAddress(IPAddress ip)
    {
        return ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
    }

    internal LookupRow[] Resolve(string input, bool verify, CancellationToken token)
    {
        IPAddress ip;
        if (TryAddress(input, out ip))
        {
            int error;
            var names = Query(ReverseName(ip), Ptr, token, out error);
            if (names.Count > 0)
                return names.Select(name => VerifyReverse(input, ip, name, verify, token)).ToArray();
            return new[] { new LookupRow(input, input, "", Describe(error, "Нет записи PTR"), canRetry: true) };
        }

        string host = ParseHost(input);
        if (host == null) return new[] { new LookupRow(input, "", "", "Некорректный IP или имя", invalid: true) };

        int v4Error, v6Error;
        var v4 = Query(host, A, token, out v4Error);
        var v6 = Query(host, Aaaa, token, out v6Error);
        if (v4.Count + v6.Count == 0)
        {
            int error = IsDnsFailure(v4Error) ? v4Error : v6Error;
            return new[] { new LookupRow(input, "", input, Describe(error, "Нет записей A или AAAA"), canRetry: true) };
        }

        return v4.Select(address => new LookupRow(input, address, input, ForwardStatus(v6Error, "A", "AAAA"), canRetry: IsDnsFailure(v6Error)))
            .Concat(v6.Select(address => new LookupRow(input, address, input, ForwardStatus(v4Error, "AAAA", "A"), canRetry: IsDnsFailure(v4Error))))
            .ToArray();
    }

    private LookupRow VerifyReverse(string input, IPAddress ip, string name, bool verify, CancellationToken token)
    {
        const string status = "Найдено (PTR)";
        if (!verify) return new LookupRow(input, input, name, status);

        ip = CanonicalAddress(ip);
        byte[] originalAddress = ip.GetAddressBytes();
        int error;
        var addresses = Query(name + ".", ip.AddressFamily == AddressFamily.InterNetwork ? A : Aaaa, token, out error);
        if (addresses.Any(address => IPAddress.Parse(address).GetAddressBytes().SequenceEqual(originalAddress)))
            return new LookupRow(input, input, name, status, "Исходный IP подтверждён");

        string verification = Describe(error, "Исходный IP отсутствует");
        return new LookupRow(input, input, name, status, verification, canRetry: true);
    }

    private static string ForwardStatus(int otherError, string found, string other)
    {
        string status = "Найдено (" + found + ")";
        return IsDnsFailure(otherError) ? status + "; " + other + ": " + Describe(otherError, "") : status;
    }

    private static string ParseHost(string input)
    {
        string host;
        try { host = new IdnMapping().GetAscii(input); }
        catch (ArgumentException) { return null; }

        if (Uri.CheckHostName(host) != UriHostNameType.Dns || host.All(c => c == '.' || Char.IsDigit(c)))
            return null;
        return host;
    }

    private static string ReverseName(IPAddress ip)
    {
        ip = CanonicalAddress(ip);
        byte[] bytes = ip.GetAddressBytes();
        Array.Reverse(bytes);
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return String.Join(".", bytes) + ".in-addr.arpa.";

        var labels = new StringBuilder(73);
        foreach (byte value in bytes)
            labels.Append((value & 15).ToString("x")).Append('.').Append((value >> 4).ToString("x")).Append('.');
        return labels.Append("ip6.arpa.").ToString();
    }

    private List<string> Query(string name, ushort type, CancellationToken token, out int error)
    {
        token.ThrowIfCancellationRequested();
        IntPtr namePtr = IntPtr.Zero, resultPtr = IntPtr.Zero, cancelPtr = IntPtr.Zero, serverPtr = IntPtr.Zero, records = IntPtr.Zero;
        var signal = new TaskCompletionSource<bool>();
        GCHandle context = GCHandle.Alloc(signal);
        var values = new List<string>();
        try
        {
            namePtr = Marshal.StringToHGlobalUni(name);
            resultPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NativeResult)));
            Marshal.StructureToPtr(new NativeResult { Version = 1 }, resultPtr, false);
            cancelPtr = Marshal.AllocHGlobal(NativeCancelSize);
            Marshal.Copy(new byte[NativeCancelSize], 0, cancelPtr, NativeCancelSize);
            if (server != null) serverPtr = AllocateServerList(server);

            var request = new NativeRequest
            {
                Version = 1,
                Name = namePtr,
                Type = type,
                Options = DnsOnly | (server == null ? 0 : WireOnly),
                Servers = serverPtr,
                Completion = Marshal.GetFunctionPointerForDelegate(Complete),
                Context = GCHandle.ToIntPtr(context)
            };
            error = DnsQueryEx(ref request, resultPtr, cancelPtr);
            if (error == Pending)
            {
                bool completed = WaitForQuery(signal.Task, cancelPtr, token);
                var result = (NativeResult)Marshal.PtrToStructure(resultPtr, typeof(NativeResult));
                records = result.Records;
                error = completed ? result.Status : Timeout;
                token.ThrowIfCancellationRequested();
            }
            else
            {
                records = ((NativeResult)Marshal.PtrToStructure(resultPtr, typeof(NativeResult))).Records;
            }
            if (error != 0) return values;
            for (IntPtr current = records; current != IntPtr.Zero; )
            {
                var record = (DnsRecord)Marshal.PtrToStructure(current, typeof(DnsRecord));
                if (record.Type == type && (record.Flags & 3) == 1) // Answer section.
                {
                    string value = ReadValue(current, record);
                    if (!String.IsNullOrEmpty(value) && !values.Contains(value, StringComparer.OrdinalIgnoreCase))
                        values.Add(value);
                }
                current = record.Next;
            }
            return values;
        }
        finally
        {
            if (records != IntPtr.Zero) DnsFree(records, FreeRecordList);
            Marshal.FreeHGlobal(serverPtr);
            Marshal.FreeHGlobal(cancelPtr);
            Marshal.FreeHGlobal(resultPtr);
            Marshal.FreeHGlobal(namePtr);
            context.Free();
        }
    }

    private bool WaitForQuery(Task completion, IntPtr cancel, CancellationToken token)
    {
        try
        {
            if (completion.Wait(timeoutMs, token)) return true;
        }
        catch (OperationCanceledException) { }

        // The native request owns its buffers until it invokes the callback, including after cancellation.
        if (!completion.IsCompleted) DnsCancelQuery(cancel);
        completion.Wait();
        return false;
    }

    private static void SignalCompletion(IntPtr context, IntPtr result)
    {
        ((TaskCompletionSource<bool>)GCHandle.FromIntPtr(context).Target).TrySetResult(true);
    }

    private static IntPtr AllocateServerList(IPAddress server)
    {
        // DNS_ADDR_ARRAY with one DNS_ADDR. Its first 32 bytes hold the native socket address.
        var buffer = new byte[ServerArrayHeaderSize + ServerAddressSize];
        buffer[0] = buffer[4] = 1; // MaxCount and AddrCount.
        SocketAddress endpoint = new IPEndPoint(server, 0).Serialize(); // DnsQueryEx selects the DNS port.
        buffer[12] = (byte)endpoint.Family;
        for (int i = 0; i < endpoint.Size; i++) buffer[ServerArrayHeaderSize + i] = endpoint[i];
        buffer[ServerArrayHeaderSize + 32] = (byte)endpoint.Size;
        IntPtr pointer = Marshal.AllocHGlobal(buffer.Length);
        Marshal.Copy(buffer, 0, pointer, buffer.Length);
        return pointer;
    }

    private static string ReadValue(IntPtr current, DnsRecord record)
    {
        if (record.Type == Ptr)
        {
            string name = Marshal.PtrToStringUni(record.Data);
            return name == null ? null : name.TrimEnd('.');
        }

        byte[] bytes = new byte[record.Type == A ? 4 : 16];
        if (record.DataLength < bytes.Length) return null;
        Marshal.Copy(IntPtr.Add(current, DataOffset), bytes, 0, bytes.Length);
        return new IPAddress(bytes).ToString();
    }

    private static bool IsDnsFailure(int error)
    {
        return error != 0 && error != NameError && error != NoRecords;
    }

    private static string Describe(int error, string normal)
    {
        if (error == Timeout || error == 10060) return "Тайм-аут DNS";
        return IsDnsFailure(error) ? String.Format("Ошибка DNS ({0})", error) : normal;
    }
}


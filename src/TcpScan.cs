using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

internal static class TcpScan
{
    internal enum State { Open, Refused, Timeout, Unavailable }

    internal static int[] ParsePorts(string input)
    {
        var ports = new SortedSet<int>();
        input = Regex.Replace(input, @"\s*-\s*", "-");
        foreach (string item in input.Split(new[] { ',', ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries))
        {
            string[] range = item.Split('-');
            int first, last;
            if (range.Length > 2 || !TryPort(range[0], out first) || !TryPort(range[range.Length - 1], out last) || last < first)
                throw new FormatException("Некорректный порт или диапазон: " + item + ". Допустимы порты от 1 до 65535.");
            for (int port = first; port <= last; port++) ports.Add(port);
        }
        if (ports.Count == 0) throw new FormatException("Укажите хотя бы один TCP-порт или диапазон.");
        return ports.ToArray();
    }

    private static bool TryPort(string input, out int port)
    {
        return Int32.TryParse(input, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port >= 1 && port <= 65535;
    }

    internal static async Task<State> Check(IPAddress ip, int port, int timeoutMs, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        try
        {
            using (var client = new TcpClient(ip.AddressFamily))
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(token))
            {
                Task connection = client.ConnectAsync(ip, port);
                Task timeout = Task.Delay(timeoutMs, deadline.Token);
                if (await Task.WhenAny(connection, timeout).ConfigureAwait(false) == connection)
                {
                    deadline.Cancel();
                    await connection.ConfigureAwait(false);
                    return State.Open;
                }

                // Disposing the client aborts the connection; observe any later socket error.
                ObserveSocketError(connection);
                token.ThrowIfCancellationRequested();
                return State.Timeout;
            }
        }
        catch (SocketException error)
        {
            if (error.SocketErrorCode == SocketError.ConnectionRefused) return State.Refused;
            return error.SocketErrorCode == SocketError.TimedOut ? State.Timeout : State.Unavailable;
        }
        catch (ArgumentException)
        {
            return State.Unavailable;
        }
    }

    private static void ObserveSocketError(Task connection)
    {
        connection.ContinueWith(t => t.Exception.Handle(error => true), CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }
}

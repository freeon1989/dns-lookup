using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new LookupWindow());
    }
}

internal sealed class LookupWindow : Form
{
    private const int AddressColumn = 1;
    private const int DnsWorkers = 8;
    private const int PortWorkers = 32;
    private static readonly Color RepeatColor = Color.FromArgb(255, 241, 176);

    private readonly TextBox input = new TextBox { Multiline = true, ScrollBars = ScrollBars.Vertical, MaxLength = 0, Dock = DockStyle.Fill };
    private readonly TextBox dnsServer = new TextBox { Width = 172, AccessibleName = "IP DNS-сервера" };
    private readonly NumericUpDown dnsTimeout = new NumericUpDown { Minimum = 1, Maximum = 60, Value = 4, Width = 54 };
    private readonly CheckBox verify = new CheckBox { Text = "Сверять PTR с A/AAAA", Checked = true, AutoSize = true, Padding = new Padding(0, 4, 0, 0) };
    private readonly TextBox portList = new TextBox { Text = "22, 80, 443, 445, 3389", Width = 218, AccessibleName = "Порты и диапазоны TCP" };
    private readonly NumericUpDown portTimeout = new NumericUpDown { Minimum = 100, Maximum = 10000, Increment = 100, Value = 800, Width = 73 };
    private readonly CheckBox issues = new CheckBox { Text = "Только ошибки", AutoSize = true, Padding = new Padding(0, 4, 0, 0) };
    private readonly Button start = CreateButton("Выполнить поиск");
    private readonly Button retry = CreateButton("Повторить запросы с ошибкой");
    private readonly Button scan = CreateButton("Сканировать TCP-порты");
    private readonly Button open = CreateButton("Открыть TXT…");
    private readonly Button stop = CreateButton("Отменить");
    private readonly Button save = CreateButton("Сохранить CSV…");
    private readonly Button copy = CreateButton("Копировать для Excel");
    private readonly TabControl tabs = new TabControl { Dock = DockStyle.Fill };
    private readonly DataGridView grid = CreateGrid("Запрос", "IP-адрес", "Имя сервера", "Статус DNS", "Сверка PTR → IP");
    private readonly DataGridView portGrid = CreateGrid("IP-адрес", "Имя сервера", "Порт TCP", "Статус");
    private readonly Label status = CreateLabel("IP с повторами выделяются жёлтым.");
    private readonly Label portStatus = CreateLabel("Показываются порты, к которым удалось подключиться по TCP.");
    private readonly System.Windows.Forms.Timer refresh = new System.Windows.Forms.Timer { Interval = 100 };
    private readonly ConcurrentQueue<Action> updates = new ConcurrentQueue<Action>();
    private readonly List<DnsEntry> entries = new List<DnsEntry>();
    private readonly Dictionary<IPAddress, DataGridViewCell> firstAddressCells = new Dictionary<IPAddress, DataGridViewCell>();
    private readonly HashSet<IPAddress> repeatedAddresses = new HashSet<IPAddress>();
    private CancellationTokenSource operation;
    private Func<string> summary;
    private Label operationStatus;

    internal LookupWindow()
    {
        Text = "DNS-поиск и TCP-порты";
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(1090, 660);
        MinimumSize = new Size(760, 510);
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1, RowCount = 5 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 86));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(CreateLabel("Введите IP и имена через пробел, запятую или с новой строки."), 0, 0);
        layout.Controls.Add(input, 0, 1);
        layout.Controls.Add(Flow(CreateLabel("IP DNS-сервера:"), dnsServer, CreateLabel("пусто = DNS Windows"),
            CreateLabel("Тайм-аут DNS (с):"), dnsTimeout), 0, 2);
        layout.Controls.Add(Flow(open, stop, save, copy), 0, 3);
        tabs.TabPages.Add(CreatePage("DNS-поиск", Flow(start, retry, verify, issues), grid, status));
        tabs.TabPages.Add(CreatePage("TCP-порты", Flow(CreateLabel("Порты:"), portList, CreateLabel("Тайм-аут (мс):"), portTimeout, scan), portGrid, portStatus));
        layout.Controls.Add(tabs, 0, 4);
        Controls.Add(layout);

        grid.Columns[4].FillWeight = 135;
        portGrid.Columns[2].ValueType = typeof(int);
        portGrid.Columns[2].FillWeight = 55;
        start.Click += async (sender, e) => await RunLookup(false);
        retry.Click += async (sender, e) => await RunLookup(true);
        scan.Click += async (sender, e) => await RunScan();
        stop.Click += (sender, e) => { stop.Enabled = false; if (operation != null) operation.Cancel(); };
        open.Click += OpenList;
        save.Click += SaveResults;
        copy.Click += CopyResults;
        issues.CheckedChanged += (sender, e) => ApplyFilter();
        tabs.SelectedIndexChanged += (sender, e) => UpdateButtons();
        refresh.Tick += (sender, e) => RefreshResults(false);
        FormClosing += (sender, e) => { if (operation != null) operation.Cancel(); };
        FormClosed += (sender, e) => refresh.Dispose();
        ActiveControl = input;
        UpdateButtons();
    }

    private static Button CreateButton(string title)
    {
        return new Button { Text = title, AutoSize = true, Padding = new Padding(6, 2, 6, 2) };
    }

    private static Label CreateLabel(string text)
    {
        return new Label { Text = text, AutoSize = true, Padding = new Padding(0, 4, 0, 2) };
    }

    private static FlowLayoutPanel Flow(params Control[] controls)
    {
        var panel = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        panel.Controls.AddRange(controls);
        return panel;
    }

    private static TabPage CreatePage(string title, Control toolbar, DataGridView table, Label footer)
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(5), ColumnCount = 1, RowCount = 3 };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.Controls.Add(toolbar, 0, 0);
        layout.Controls.Add(table, 0, 1);
        layout.Controls.Add(footer, 0, 2);
        var page = new TabPage(title) { UseVisualStyleBackColor = true };
        page.Controls.Add(layout);
        return page;
    }

    private static DataGridView CreateGrid(params string[] headers)
    {
        var table = new DataGridView
        {
            Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false,
            RowHeadersVisible = false, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            BackgroundColor = SystemColors.Window, ClipboardCopyMode = DataGridViewClipboardCopyMode.EnableWithoutHeaderText
        };
        foreach (string header in headers)
            table.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = header, SortMode = DataGridViewColumnSortMode.Automatic });
        return table;
    }

    private string[] ReadInput()
    {
        return input.Text.Split(new[] { ' ', '\t', '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
    }

    private DnsLookup ReadDnsSettings(Label footer)
    {
        string address = dnsServer.Text.Trim();
        IPAddress server = null;
        if (address.Length > 0 && !DnsLookup.TryAddress(address, out server))
        {
            footer.Text = "Укажите IP-адрес DNS-сервера или оставьте поле пустым.";
            dnsServer.Focus();
            return null;
        }
        return new DnsLookup(server == null ? null : DnsLookup.CanonicalAddress(server), (int)dnsTimeout.Value * 1000);
    }

    private async Task RunLookup(bool retryIssues)
    {
        var lookup = ReadDnsSettings(status);
        if (lookup == null) return;
        DnsEntry[] targets;
        if (retryIssues)
        {
            targets = entries.Where(entry => entry.NeedsRetry).ToArray();
        }
        else
        {
            string[] items = ReadInput();
            if (items.Length == 0)
            {
                status.Text = "Добавьте хотя бы один IP-адрес или имя сервера.";
                input.Focus();
                return;
            }
            targets = items.Select(item => new DnsEntry(item)).ToArray();
            entries.Clear();
            entries.AddRange(targets);
        }

        bool verifyPtr = verify.Checked;
        var retried = retryIssues ? new HashSet<DnsEntry>(targets) : null;
        RebuildDnsGrid(retried);
        int completed = 0;
        await Execute(status, token => Task.Run(() =>
        {
            Parallel.ForEach(targets, new ParallelOptions { MaxDegreeOfParallelism = DnsWorkers, CancellationToken = token }, entry =>
            {
                LookupRow[] rows = lookup.Resolve(entry.Input, verifyPtr, token);
                updates.Enqueue(() =>
                {
                    entry.Rows = rows;
                    AddDnsRows(rows);
                    completed++;
                });
            });
        }), () => String.Format("Запросов выполнено: {0:N0} из {1:N0}   |   Строк: {2:N0}   |   IP с повторами: {3:N0}",
            completed, targets.Length, grid.Rows.Count, repeatedAddresses.Count), () => RebuildDnsGrid(null));
    }

    private void RebuildDnsGrid(HashSet<DnsEntry> omitted)
    {
        DataGridViewColumn sortedColumn = grid.SortedColumn;
        SortOrder sortOrder = grid.SortOrder;
        grid.Rows.Clear();
        firstAddressCells.Clear();
        repeatedAddresses.Clear();
        foreach (DnsEntry entry in entries)
            if (entry.Rows != null && (omitted == null || !omitted.Contains(entry))) AddDnsRows(entry.Rows);
        if (sortedColumn != null && sortOrder != SortOrder.None && grid.Rows.Count > 0)
            grid.Sort(sortedColumn, sortOrder == SortOrder.Ascending ? ListSortDirection.Ascending : ListSortDirection.Descending);
    }

    private void AddDnsRows(IEnumerable<LookupRow> rows)
    {
        foreach (LookupRow result in rows)
        {
            var row = new DataGridViewRow { Tag = result };
            row.CreateCells(grid, result.Values);
            grid.Rows.Add(row);
            if (issues.Checked && !result.IsIssue) row.Visible = false;

            if (result.Values[AddressColumn].Length == 0) continue;
            IPAddress ip = DnsLookup.CanonicalAddress(IPAddress.Parse(result.Values[AddressColumn]));
            DataGridViewCell address = row.Cells[AddressColumn];
            DataGridViewCell first;
            if (!firstAddressCells.TryGetValue(ip, out first))
            {
                firstAddressCells.Add(ip, address);
                continue;
            }
            if (repeatedAddresses.Add(ip)) MarkRepeated(first);
            MarkRepeated(address);
        }
    }

    private static void MarkRepeated(DataGridViewCell cell)
    {
        cell.Style.BackColor = RepeatColor;
        cell.Style.SelectionBackColor = Color.FromArgb(255, 208, 91);
        cell.Style.SelectionForeColor = SystemColors.WindowText;
        cell.ToolTipText = "Этот IP есть в нескольких строках DNS-результатов.";
    }

    private void ApplyFilter()
    {
        grid.CurrentCell = null;
        foreach (DataGridViewRow row in grid.Rows)
            row.Visible = !issues.Checked || ((LookupRow)row.Tag).IsIssue;
        UpdateButtons();
    }

    private async Task RunScan()
    {
        string[] items = ReadInput().Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (items.Length == 0)
        {
            portStatus.Text = "Добавьте хотя бы один IP-адрес или имя сервера.";
            input.Focus();
            return;
        }
        var lookup = ReadDnsSettings(portStatus);
        if (lookup == null) return;

        int[] ports;
        try { ports = TcpScan.ParsePorts(portList.Text); }
        catch (FormatException error) { portStatus.Text = error.Message; portList.Focus(); return; }

        portGrid.Rows.Clear();
        int timeout = (int)portTimeout.Value;
        int resolved = 0, unresolved = 0;
        var scanProgress = new ScanProgress();
        await Execute(portStatus, token => Task.Run(async () =>
        {
            var addresses = new ConcurrentBag<KeyValuePair<IPAddress, string>>();
            Parallel.ForEach(items, new ParallelOptions { MaxDegreeOfParallelism = DnsWorkers, CancellationToken = token }, item =>
            {
                IPAddress ip;
                if (DnsLookup.TryAddress(item, out ip))
                {
                    addresses.Add(new KeyValuePair<IPAddress, string>(DnsLookup.CanonicalAddress(ip), ""));
                }
                else
                {
                    LookupRow[] rows = lookup.Resolve(item, false, token);
                    if (!rows.Any(row => row.HasMatch)) Interlocked.Increment(ref unresolved);
                    foreach (LookupRow row in rows.Where(row => row.HasMatch))
                        addresses.Add(new KeyValuePair<IPAddress, string>(DnsLookup.CanonicalAddress(IPAddress.Parse(row.Values[1])), item));
                }
                Interlocked.Increment(ref resolved);
            });

            var targets = addresses.GroupBy(pair => pair.Key).Select(group => new KeyValuePair<IPAddress, string>(group.Key,
                String.Join(", ", group.Select(pair => pair.Value).Where(name => name.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase)))).ToArray();
            Interlocked.Exchange(ref scanProgress.Total, (long)targets.Length * ports.Length);
            int workers = (int)Math.Min(PortWorkers, Interlocked.Read(ref scanProgress.Total));
            await Task.WhenAll(Enumerable.Range(0, workers).Select(i => ScanPorts(targets, ports, timeout, scanProgress, token))).ConfigureAwait(false);
        }), () =>
        {
            long total = Interlocked.Read(ref scanProgress.Total);
            if (total < 0) return String.Format("Подготовка адресов: {0:N0} из {1:N0}   |   Без IP: {2:N0}", Volatile.Read(ref resolved), items.Length, Volatile.Read(ref unresolved));
            return String.Format("Проверено: {0:N0} из {1:N0}   |   Открыто: {2:N0}   |   Отказ: {3:N0}   |   Тайм-аут: {4:N0}   |   Другие ошибки: {5:N0}   |   Без IP: {6:N0}",
                Interlocked.Read(ref scanProgress.Completed), total, portGrid.Rows.Count, Interlocked.Read(ref scanProgress.Refused),
                Interlocked.Read(ref scanProgress.Timeouts), Interlocked.Read(ref scanProgress.Unavailable), Volatile.Read(ref unresolved));
        });
    }

    private async Task ScanPorts(KeyValuePair<IPAddress, string>[] targets, int[] ports, int timeout, ScanProgress progress, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            long job = Interlocked.Increment(ref progress.Next);
            if (job >= progress.Total) return;
            var target = targets[job / ports.Length];
            int port = ports[job % ports.Length];
            TcpScan.State result = await TcpScan.Check(target.Key, port, timeout, token).ConfigureAwait(false);
            switch (result)
            {
                case TcpScan.State.Open:
                    updates.Enqueue(() => portGrid.Rows.Add(target.Key.ToString(), target.Value, port, "Открыт"));
                    break;
                case TcpScan.State.Refused: Interlocked.Increment(ref progress.Refused); break;
                case TcpScan.State.Timeout: Interlocked.Increment(ref progress.Timeouts); break;
                case TcpScan.State.Unavailable: Interlocked.Increment(ref progress.Unavailable); break;
            }
            Interlocked.Increment(ref progress.Completed);
        }
    }

    private async Task Execute(Label footer, Func<CancellationToken, Task> run, Func<string> getSummary, Action finish = null)
    {
        using (var cancellation = new CancellationTokenSource())
        {
            operation = cancellation;
            operationStatus = footer;
            summary = getSummary;
            UpdateButtons();
            RefreshResults(false);
            refresh.Start();
            string failure = null;
            try { await run(cancellation.Token); }
            catch (OperationCanceledException error)
            {
                if (!cancellation.IsCancellationRequested) failure = error.Message;
            }
            catch (Exception error) { failure = error.GetBaseException().Message; }
            finally
            {
                if (!IsDisposed)
                {
                    refresh.Stop();
                    RefreshResults(true);
                    if (finish != null) finish();
                    footer.Text = failure != null ? "Ошибка: " + failure : (cancellation.IsCancellationRequested ? "Остановлено. " : "Готово. ") + summary();
                    operation = null;
                    UpdateButtons();
                }
            }
        }
    }

    private void RefreshResults(bool flush)
    {
        if (operation == null) return;
        Action update;
        for (int i = 0; (flush || i < 500) && updates.TryDequeue(out update); i++) update();
        operationStatus.Text = (operation.IsCancellationRequested ? "Остановка… " : "Выполняется… ") + summary();
        UpdateButtons();
    }

    private DataGridView ActiveGrid { get { return tabs.SelectedIndex == 1 ? portGrid : grid; } }

    private void UpdateButtons()
    {
        bool idle = operation == null;
        start.Enabled = scan.Enabled = open.Enabled = dnsServer.Enabled = dnsTimeout.Enabled = verify.Enabled = portList.Enabled = portTimeout.Enabled = idle;
        input.ReadOnly = !idle;
        retry.Enabled = idle && entries.Any(entry => entry.NeedsRetry);
        stop.Enabled = !idle && !operation.IsCancellationRequested;
        save.Enabled = copy.Enabled = ActiveGrid.Rows.GetFirstRow(DataGridViewElementStates.Visible) >= 0;
    }

    private void OpenList(object sender, EventArgs e)
    {
        using (var dialog = new OpenFileDialog { Filter = "Текстовый список (*.txt)|*.txt|Все файлы (*.*)|*.*" })
        {
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            try { input.Text = File.ReadAllText(dialog.FileName); }
            catch (IOException error) { ShowError(error, "Ошибка файла"); }
            catch (UnauthorizedAccessException error) { ShowError(error, "Ошибка файла"); }
        }
    }

    private void SaveResults(object sender, EventArgs e)
    {
        var table = ActiveGrid;
        using (var dialog = new SaveFileDialog { Filter = "Таблица CSV (*.csv)|*.csv", FileName = table == grid ? "dns-results.csv" : "tcp-ports.csv" })
        {
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            try { WriteCsv(dialog.FileName, VisibleRows(table)); }
            catch (IOException error) { ShowError(error, "Ошибка файла"); }
            catch (UnauthorizedAccessException error) { ShowError(error, "Ошибка файла"); }
        }
    }

    private void CopyResults(object sender, EventArgs e)
    {
        string text = String.Join(Environment.NewLine, VisibleRows(ActiveGrid).Select(row => String.Join("\t",
            row.Select(cell => ProtectSpreadsheetCell(cell.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' '))))));
        try { Clipboard.SetText(text); }
        catch (System.Runtime.InteropServices.ExternalException error) { ShowError(error, "Ошибка буфера обмена"); }
    }

    private static IEnumerable<string[]> VisibleRows(DataGridView table)
    {
        yield return table.Columns.Cast<DataGridViewColumn>().Select(column => column.HeaderText).ToArray();
        foreach (DataGridViewRow row in table.Rows)
            if (row.Visible) yield return row.Cells.Cast<DataGridViewCell>().Select(cell => Convert.ToString(cell.Value)).ToArray();
    }

    private static void WriteCsv(string path, IEnumerable<string[]> rows)
    {
        using (var writer = new StreamWriter(path, false, new UTF8Encoding(true)))
            foreach (string[] row in rows)
                writer.WriteLine(String.Join(";", row.Select(cell => "\"" + ProtectSpreadsheetCell(cell).Replace("\"", "\"\"") + "\"")));
    }

    private static string ProtectSpreadsheetCell(string value)
    {
        string trimmed = value.TrimStart();
        return trimmed.Length > 0 && "=+-@".IndexOf(trimmed[0]) >= 0 ? "'" + value : value;
    }

    private void ShowError(Exception error, string title)
    {
        MessageBox.Show(this, error.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    private sealed class DnsEntry
    {
        internal readonly string Input;
        internal LookupRow[] Rows;
        internal bool NeedsRetry { get { return Rows != null && Rows.Any(row => row.CanRetry); } }
        internal DnsEntry(string input) { Input = input; }
    }

    private sealed class ScanProgress
    {
        internal long Next = -1, Total = -1, Completed, Refused, Timeouts, Unavailable;
    }
}

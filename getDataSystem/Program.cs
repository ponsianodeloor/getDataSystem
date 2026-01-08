using System.DirectoryServices;
using System.Globalization;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed class Program
{
    internal const string EndpointEnvVar = "GETDATASYSTEM_ENDPOINT";

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
        Converters = { new DateTimeOffsetJsonConverter() },
    };

    private const double BytesPerGb = 1024d * 1024d * 1024d;

    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm(args));
    }

    internal static SystemReport BuildReport()
    {
        var errors = new List<CollectionError>();

        var user = new UserInfo
        {
            UserName = Environment.UserName,
            UserDomain = Environment.UserDomainName,
        };

        var deviceId = BuildDeviceId(errors);
        var ad = GetAdUserInfo();
        var cpu = GetCpuInfo(errors);
        var memory = GetMemoryInfo(errors);
        var disks = new DiskInfo
        {
            Physical = GetPhysicalDisks(errors).ToArray(),
            Partitions = GetPartitions(errors).ToArray(),
            Logical = GetLogicalDisks(errors).ToArray(),
        };
        var networkInterfaces = GetNetworkInterfaces(errors);

        return new SystemReport
        {
            DeviceId = deviceId,
            CollectedAt = DateTimeOffset.UtcNow,
            Hostname = Environment.MachineName,
            User = user,
            Ad = ad,
            Cpu = cpu.ToArray(),
            Memory = memory,
            Disks = disks,
            NetworkInterfaces = networkInterfaces.ToArray(),
            Errors = errors.Count > 0 ? errors.ToArray() : null,
        };
    }

    internal static string? GetEndpoint(string[] args)
    {
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (arg.StartsWith("--endpoint=", StringComparison.OrdinalIgnoreCase))
            {
                return arg.Substring("--endpoint=".Length).Trim();
            }

            if (string.Equals(arg, "--endpoint", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                return args[i + 1].Trim();
            }
        }

        var envValue = Environment.GetEnvironmentVariable(EndpointEnvVar);
        return string.IsNullOrWhiteSpace(envValue) ? null : envValue.Trim();
    }

    private static string BuildDeviceId(List<CollectionError> errors)
    {
        var host = Environment.MachineName;
        var serial = NormalizeSerial(GetBiosSerial(errors)) ?? NormalizeSerial(GetBaseBoardSerial(errors));
        var source = string.IsNullOrWhiteSpace(serial) ? host : $"{host}|{serial}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(source));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? NormalizeSerial(string? serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return null;
        }

        var trimmed = serial.Trim();
        var lower = trimmed.ToLowerInvariant();
        if (lower is "to be filled by o.e.m." or "none" or "default string" or "unknown" or "not applicable")
        {
            return null;
        }

        return trimmed;
    }

    private static string? GetBiosSerial(List<CollectionError> errors)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("root\\cimv2", "SELECT SerialNumber FROM Win32_BIOS");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                var serial = GetString(mo, "SerialNumber");
                if (!string.IsNullOrWhiteSpace(serial))
                {
                    return serial;
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "bios", Message = ex.Message });
        }

        return null;
    }

    private static string? GetBaseBoardSerial(List<CollectionError> errors)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("root\\cimv2", "SELECT SerialNumber FROM Win32_BaseBoard");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                var serial = GetString(mo, "SerialNumber");
                if (!string.IsNullOrWhiteSpace(serial))
                {
                    return serial;
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "baseboard", Message = ex.Message });
        }

        return null;
    }

    private static AdUserInfo GetAdUserInfo()
    {
        var adInfo = new AdUserInfo
        {
            Status = "not_available",
            Source = "ldap",
        };

        try
        {
            using var root = new DirectoryEntry("LDAP://RootDSE");
            var namingContext = root.Properties["defaultNamingContext"]?.Value?.ToString();
            if (string.IsNullOrWhiteSpace(namingContext))
            {
                adInfo.Message = "Default naming context not found.";
                return adInfo;
            }

            using var searchRoot = new DirectoryEntry($"LDAP://{namingContext}");
            using var searcher = new DirectorySearcher(searchRoot)
            {
                Filter =
                    $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={EscapeLdapFilterValue(Environment.UserName)}))",
                SearchScope = SearchScope.Subtree,
                PageSize = 1,
            };
            searcher.PropertiesToLoad.AddRange(new[] { "mail", "displayName", "department", "memberOf" });

            var result = searcher.FindOne();
            if (result == null)
            {
                adInfo.Status = "not_found";
                adInfo.Message = "User not found in AD.";
                return adInfo;
            }

            adInfo.Status = "ok";
            adInfo.Email = GetResultProperty(result, "mail");
            adInfo.DisplayName = GetResultProperty(result, "displayName");
            adInfo.Department = GetResultProperty(result, "department");
            adInfo.Groups = GetResultProperties(result, "memberOf")
                .Select(ParseGroupName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex)
        {
            adInfo.Status = "not_available";
            adInfo.Message = ex.Message;
        }

        return adInfo;
    }

    private static List<CpuInfo> GetCpuInfo(List<CollectionError> errors)
    {
        var cpuList = new List<CpuInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, Manufacturer, ProcessorId FROM Win32_Processor");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                cpuList.Add(new CpuInfo
                {
                    Name = GetString(mo, "Name"),
                    Manufacturer = GetString(mo, "Manufacturer"),
                    ProcessorId = GetString(mo, "ProcessorId"),
                    NumberOfCores = GetUInt32(mo, "NumberOfCores"),
                    NumberOfLogicalProcessors = GetUInt32(mo, "NumberOfLogicalProcessors"),
                    MaxClockSpeedMHz = GetUInt32(mo, "MaxClockSpeed"),
                });
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "cpu", Message = ex.Message });
        }

        return cpuList;
    }

    private static MemoryInfo GetMemoryInfo(List<CollectionError> errors)
    {
        ulong? totalPhysicalBytes = null;
        ulong? totalVisibleBytes = null;
        ulong? freeBytes = null;

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                totalPhysicalBytes = GetUInt64(mo, "TotalPhysicalMemory");
                break;
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "memory_total", Message = ex.Message });
        }

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT FreePhysicalMemory, TotalVisibleMemorySize FROM Win32_OperatingSystem");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                var freeKb = GetUInt64(mo, "FreePhysicalMemory");
                var totalVisibleKb = GetUInt64(mo, "TotalVisibleMemorySize");
                freeBytes = freeKb.HasValue ? freeKb.Value * 1024 : null;
                totalVisibleBytes = totalVisibleKb.HasValue ? totalVisibleKb.Value * 1024 : null;
                break;
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "memory_usage", Message = ex.Message });
        }

        ulong? usedBytes = null;
        if (totalVisibleBytes.HasValue && freeBytes.HasValue)
        {
            usedBytes = totalVisibleBytes.Value - freeBytes.Value;
        }

        double? usedPercent = null;
        if (usedBytes.HasValue && totalVisibleBytes.HasValue && totalVisibleBytes.Value > 0)
        {
            usedPercent = Math.Round(usedBytes.Value * 100d / totalVisibleBytes.Value, 2);
        }

        return new MemoryInfo
        {
            TotalPhysicalGb = BytesToGb(totalPhysicalBytes),
            TotalVisibleGb = BytesToGb(totalVisibleBytes),
            FreePhysicalGb = BytesToGb(freeBytes),
            UsedPhysicalGb = BytesToGb(usedBytes),
            UsedPercent = usedPercent,
        };
    }

    private static double? BytesToGb(ulong? bytes)
    {
        if (!bytes.HasValue)
        {
            return null;
        }

        return Math.Round(bytes.Value / BytesPerGb, 2);
    }

    private static List<PhysicalDiskInfo> GetPhysicalDisks(List<CollectionError> errors)
    {
        var disks = new List<PhysicalDiskInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT Index, DeviceID, Model, SerialNumber, Size, InterfaceType, MediaType, PNPDeviceID FROM Win32_DiskDrive");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                var model = GetString(mo, "Model");
                var mediaType = GetString(mo, "MediaType");
                var pnpId = GetString(mo, "PNPDeviceID");
                var interfaceType = GetString(mo, "InterfaceType");

                disks.Add(new PhysicalDiskInfo
                {
                    Index = GetInt32(mo, "Index"),
                    DeviceId = GetString(mo, "DeviceID"),
                    Model = model,
                    SerialNumber = GetString(mo, "SerialNumber")?.Trim(),
                    SizeGb = BytesToGb(GetUInt64(mo, "Size")),
                    InterfaceType = interfaceType,
                    MediaType = mediaType,
                    PnpDeviceId = pnpId,
                    DriveType = InferDriveType(mediaType, model, pnpId, interfaceType),
                });
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "physical_disks", Message = ex.Message });
        }

        return disks;
    }

    private static List<PartitionInfo> GetPartitions(List<CollectionError> errors)
    {
        var partitions = new List<PartitionInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT DeviceID, DiskIndex, Index, Size, Type, Bootable, PrimaryPartition FROM Win32_DiskPartition");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                partitions.Add(new PartitionInfo
                {
                    DeviceId = GetString(mo, "DeviceID"),
                    DiskIndex = GetInt32(mo, "DiskIndex"),
                    Index = GetInt32(mo, "Index"),
                    SizeGb = BytesToGb(GetUInt64(mo, "Size")),
                    Type = GetString(mo, "Type"),
                    Bootable = GetBool(mo, "Bootable"),
                    PrimaryPartition = GetBool(mo, "PrimaryPartition"),
                });
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "partitions", Message = ex.Message });
        }

        return partitions;
    }

    private static List<LogicalDiskInfo> GetLogicalDisks(List<CollectionError> errors)
    {
        var disks = new List<LogicalDiskInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT DeviceID, FileSystem, Size, FreeSpace, DriveType, VolumeName FROM Win32_LogicalDisk");
            using var results = searcher.Get();
            foreach (ManagementObject mo in results)
            {
                var sizeBytes = GetUInt64(mo, "Size");
                var freeBytes = GetUInt64(mo, "FreeSpace");
                double? usedPercent = null;
                if (sizeBytes.HasValue && freeBytes.HasValue && sizeBytes.Value > 0)
                {
                    usedPercent = Math.Round((sizeBytes.Value - freeBytes.Value) * 100d / sizeBytes.Value, 2);
                }

                disks.Add(new LogicalDiskInfo
                {
                    DeviceId = GetString(mo, "DeviceID"),
                    FileSystem = GetString(mo, "FileSystem"),
                    SizeGb = BytesToGb(sizeBytes),
                    FreeGb = BytesToGb(freeBytes),
                    UsedPercent = usedPercent,
                    DriveType = GetUInt32(mo, "DriveType"),
                    VolumeName = GetString(mo, "VolumeName"),
                });
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "logical_disks", Message = ex.Message });
        }

        return disks;
    }

    private static List<NetworkInterfaceInfo> GetNetworkInterfaces(List<CollectionError> errors)
    {
        var interfaces = new List<NetworkInterfaceInfo>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                var ipAddresses = ni.GetIPProperties()
                    .UnicastAddresses
                    .Select(address => address.Address)
                    .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(NormalizeIpAddress)
                    .Where(address => !string.IsNullOrWhiteSpace(address))
                    .ToArray();

                if (ipAddresses.Length == 0)
                {
                    continue;
                }

                interfaces.Add(new NetworkInterfaceInfo
                {
                    Type = GetNetworkType(ni),
                    VirtualMachine = IsVirtualAdapter(ni),
                    MacAddress = FormatMacAddress(ni.GetPhysicalAddress()),
                    IpAddresses = ipAddresses,
                });
            }
        }
        catch (Exception ex)
        {
            errors.Add(new CollectionError { Section = "network", Message = ex.Message });
        }

        return interfaces;
    }

    private static string EscapeLdapFilterValue(string value)
    {
        var sb = new StringBuilder();
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\':
                    sb.Append(@"\5c");
                    break;
                case '*':
                    sb.Append(@"\2a");
                    break;
                case '(':
                    sb.Append(@"\28");
                    break;
                case ')':
                    sb.Append(@"\29");
                    break;
                case '\0':
                    sb.Append(@"\00");
                    break;
                default:
                    sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    private static string? GetResultProperty(SearchResult result, string propertyName)
    {
        if (!result.Properties.Contains(propertyName) || result.Properties[propertyName].Count == 0)
        {
            return null;
        }

        return result.Properties[propertyName][0]?.ToString();
    }

    private static IEnumerable<string> GetResultProperties(SearchResult result, string propertyName)
    {
        if (!result.Properties.Contains(propertyName) || result.Properties[propertyName].Count == 0)
        {
            return Array.Empty<string>();
        }

        return result.Properties[propertyName]
            .Cast<object>()
            .Select(value => value?.ToString())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!);
    }

    private static string? ParseGroupName(string? distinguishedName)
    {
        if (string.IsNullOrWhiteSpace(distinguishedName))
        {
            return null;
        }

        var parts = distinguishedName.Split(',');
        foreach (var part in parts)
        {
            if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return part.Substring(3);
            }
        }

        return distinguishedName;
    }

    private static string? InferDriveType(string? mediaType, string? model, string? pnpId, string? interfaceType)
    {
        var combined = string.Join(" ", new[] { mediaType, model, pnpId, interfaceType })
            .ToUpperInvariant();

        if (combined.Contains("NVME") || combined.Contains("SSD") || combined.Contains("SOLID STATE"))
        {
            return "SSD";
        }

        if (combined.Contains("USB"))
        {
            return "USB";
        }

        if (combined.Contains("HDD") || combined.Contains("HARD DISK") || combined.Contains("SATA") ||
            combined.Contains("IDE") || combined.Contains("SCSI"))
        {
            return "HDD";
        }

        return "Unknown";
    }

    private static string? GetString(ManagementBaseObject obj, string propertyName)
        => obj[propertyName]?.ToString();

    private static string? NormalizeIpAddress(IPAddress? address)
    {
        if (address == null)
        {
            return null;
        }

        var text = address.ToString();
        var percentIndex = text.IndexOf('%');
        return percentIndex > 0 ? text.Substring(0, percentIndex) : text;
    }

    private static string? FormatMacAddress(PhysicalAddress? address)
    {
        if (address == null)
        {
            return null;
        }

        var bytes = address.GetAddressBytes();
        if (bytes.Length == 0)
        {
            return null;
        }

        return string.Join(":", bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)))
            .ToLowerInvariant();
    }

    private static string GetNetworkType(NetworkInterface ni)
    {
        return ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? "wifi" : "local";
    }

    private static bool IsVirtualAdapter(NetworkInterface ni)
    {
        var text = $"{ni.Description} {ni.Name}";
        return ContainsAny(text, new[]
        {
            "virtual",
            "vmware",
            "virtualbox",
            "vbox",
            "hyper-v",
            "hyperv",
            "vmswitch",
            "vethernet",
            "virtio",
            "kvm",
            "xen",
            "qemu",
            "parallels",
            "vmbus",
            "vmnet"
        });
    }

    private static bool ContainsAny(string? text, string[] markers)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        foreach (var marker in markers)
        {
            if (text.IndexOf(marker, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    private static uint? GetUInt32(ManagementBaseObject obj, string propertyName)
        => TryConvert(obj[propertyName], Convert.ToUInt32);

    private static ulong? GetUInt64(ManagementBaseObject obj, string propertyName)
        => TryConvert(obj[propertyName], Convert.ToUInt64);

    private static int? GetInt32(ManagementBaseObject obj, string propertyName)
        => TryConvert(obj[propertyName], Convert.ToInt32);

    private static bool? GetBool(ManagementBaseObject obj, string propertyName)
        => TryConvert(obj[propertyName], Convert.ToBoolean);

    private static T? TryConvert<T>(object? value, Func<object, T> convert) where T : struct
    {
        if (value == null)
        {
            return null;
        }

        try
        {
            return convert(value);
        }
        catch
        {
            return null;
        }
    }
}

internal sealed class DateTimeOffsetJsonConverter : JsonConverter<DateTimeOffset>
{
    private const string Format = "yyyy-MM-dd HH:mm:ss";

    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var text = reader.GetString();
        if (string.IsNullOrWhiteSpace(text))
        {
            return default;
        }

        if (DateTimeOffset.TryParseExact(
                text,
                Format,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var parsed))
        {
            return parsed;
        }

        return DateTimeOffset.Parse(
            text,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.UtcDateTime.ToString(Format, CultureInfo.InvariantCulture));
    }
}

internal sealed class MainForm : Form
{
    private readonly Label _statusLabel;
    private readonly TextBox _jsonTextBox;
    private readonly string? _endpoint;

    public MainForm(string[] args)
    {
        _endpoint = Program.GetEndpoint(args);

        Text = "Obtener datos del sistema - getDataSystem - Secap";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(720, 480);

        _statusLabel = new Label
        {
            AutoSize = true,
            Text = "Preparando..."
        };

        _jsonTextBox = new TextBox
        {
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = new Font(FontFamily.GenericMonospace, 9f),
            Dock = DockStyle.Fill
        };

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            Padding = new Padding(12)
        };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100f));
        layout.Controls.Add(_statusLabel, 0, 0);
        layout.Controls.Add(_jsonTextBox, 0, 1);

        Controls.Add(layout);

        Shown += async (_, __) => await LoadReportAsync();
    }

    private async Task LoadReportAsync()
    {
        _statusLabel.Text = "Recolectando...";

        SystemReport report;
        try
        {
            report = await Task.Run(Program.BuildReport);
        }
        catch (Exception ex)
        {
            _statusLabel.Text = $"Error: {ex.Message}";
            return;
        }

        var json = JsonSerializer.Serialize(report, Program.JsonOptions);
        _jsonTextBox.Text = json;

        if (string.IsNullOrWhiteSpace(_endpoint))
        {
            _statusLabel.Text = $"Endpoint no configurado. Use --endpoint o {Program.EndpointEnvVar}.";
            return;
        }

        _statusLabel.Text = "Enviando...";

        using var client = new HttpClient();
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        try
        {
            using var response = await client.PostAsync(_endpoint, content);
            if (!response.IsSuccessStatusCode)
            {
                _statusLabel.Text = $"POST failed: {(int)response.StatusCode} {response.ReasonPhrase}";
                return;
            }
        }
        catch (Exception ex)
        {
            _statusLabel.Text = $"POST failed: {ex.Message}";
            return;
        }

        _statusLabel.Text = "Todo correcto";
    }
}

internal sealed class SystemReport
{
    public string DeviceId { get; init; } = string.Empty;
    public DateTimeOffset CollectedAt { get; init; }
    public string Hostname { get; init; } = string.Empty;
    public UserInfo User { get; init; } = new();
    public AdUserInfo Ad { get; init; } = new();
    public CpuInfo[] Cpu { get; init; } = Array.Empty<CpuInfo>();
    public MemoryInfo Memory { get; init; } = new();
    public DiskInfo Disks { get; init; } = new();
    public NetworkInterfaceInfo[] NetworkInterfaces { get; init; } = Array.Empty<NetworkInterfaceInfo>();
    public CollectionError[]? Errors { get; init; }
}

internal sealed class UserInfo
{
    public string UserName { get; init; } = string.Empty;
    public string UserDomain { get; init; } = string.Empty;
}

internal sealed class AdUserInfo
{
    public string Status { get; set; } = "not_available";
    public string? Source { get; set; }
    public string? Message { get; set; }
    public string? Email { get; set; }
    public string? DisplayName { get; set; }
    public string? Department { get; set; }
    public string[]? Groups { get; set; }
}

internal sealed class CpuInfo
{
    public string? Name { get; init; }
    public string? Manufacturer { get; init; }
    public string? ProcessorId { get; init; }
    public uint? NumberOfCores { get; init; }
    public uint? NumberOfLogicalProcessors { get; init; }
    public uint? MaxClockSpeedMHz { get; init; }
}

internal sealed class MemoryInfo
{
    public double? TotalPhysicalGb { get; init; }
    public double? TotalVisibleGb { get; init; }
    public double? FreePhysicalGb { get; init; }
    public double? UsedPhysicalGb { get; init; }
    public double? UsedPercent { get; init; }
}

internal sealed class DiskInfo
{
    public PhysicalDiskInfo[] Physical { get; init; } = Array.Empty<PhysicalDiskInfo>();
    public PartitionInfo[] Partitions { get; init; } = Array.Empty<PartitionInfo>();
    public LogicalDiskInfo[] Logical { get; init; } = Array.Empty<LogicalDiskInfo>();
}

internal sealed class PhysicalDiskInfo
{
    public int? Index { get; init; }
    public string? DeviceId { get; init; }
    public string? Model { get; init; }
    public string? SerialNumber { get; init; }
    public double? SizeGb { get; init; }
    public string? InterfaceType { get; init; }
    public string? MediaType { get; init; }
    public string? PnpDeviceId { get; init; }
    public string? DriveType { get; init; }
}

internal sealed class PartitionInfo
{
    public string? DeviceId { get; init; }
    public int? DiskIndex { get; init; }
    public int? Index { get; init; }
    public double? SizeGb { get; init; }
    public string? Type { get; init; }
    public bool? Bootable { get; init; }
    public bool? PrimaryPartition { get; init; }
}

internal sealed class LogicalDiskInfo
{
    public string? DeviceId { get; init; }
    public string? FileSystem { get; init; }
    public double? SizeGb { get; init; }
    public double? FreeGb { get; init; }
    public double? UsedPercent { get; init; }
    public uint? DriveType { get; init; }
    public string? VolumeName { get; init; }
}

internal sealed class NetworkInterfaceInfo
{
    public string Type { get; init; } = "local";
    public bool VirtualMachine { get; init; }
    public string? MacAddress { get; init; }
    public string[] IpAddresses { get; init; } = Array.Empty<string>();
}

internal sealed class CollectionError
{
    public string Section { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

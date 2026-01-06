using System.DirectoryServices;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

internal sealed class Program
{
    private const string EndpointEnvVar = "GETDATASYSTEM_ENDPOINT";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    private static async Task<int> Main(string[] args)
    {
        var endpoint = GetEndpoint(args);
        var report = BuildReport();
        var json = JsonSerializer.Serialize(report, JsonOptions);

        Console.WriteLine(json);

        if (string.IsNullOrWhiteSpace(endpoint))
        {
            Console.Error.WriteLine($"Endpoint not set. Use --endpoint or {EndpointEnvVar}.");
            return 1;
        }

        using var client = new HttpClient();
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        try
        {
            using var response = await client.PostAsync(endpoint, content);
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine($"POST failed: {(int)response.StatusCode} {response.ReasonPhrase}");
                return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"POST failed: {ex.Message}");
            return 3;
        }

        return 0;
    }

    private static SystemReport BuildReport()
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
        var smartHealth = GetSmartHealth();

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
            SmartHealth = smartHealth,
            Errors = errors.Count > 0 ? errors.ToArray() : null,
        };
    }

    private static string? GetEndpoint(string[] args)
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
            TotalPhysicalBytes = totalPhysicalBytes,
            TotalVisibleBytes = totalVisibleBytes,
            FreePhysicalBytes = freeBytes,
            UsedPhysicalBytes = usedBytes,
            UsedPercent = usedPercent,
        };
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
                    SizeBytes = GetUInt64(mo, "Size"),
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
                    SizeBytes = GetUInt64(mo, "Size"),
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
                    SizeBytes = sizeBytes,
                    FreeBytes = freeBytes,
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
                    .Select(address => address.Address.ToString())
                    .Where(address => !string.IsNullOrWhiteSpace(address))
                    .ToArray();
                var macAddress = ni.GetPhysicalAddress()?.ToString();

                if (ipAddresses.Length == 0 && string.IsNullOrWhiteSpace(macAddress))
                {
                    continue;
                }

                interfaces.Add(new NetworkInterfaceInfo
                {
                    Name = ni.Name,
                    Description = ni.Description,
                    Type = ni.NetworkInterfaceType.ToString(),
                    Status = ni.OperationalStatus.ToString(),
                    Speed = ni.Speed > 0 ? ni.Speed : null,
                    MacAddress = string.IsNullOrWhiteSpace(macAddress) ? null : macAddress,
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

    private static SmartHealthInfo GetSmartHealth()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\WMI",
                "SELECT InstanceName, PredictFailure FROM MSStorageDriver_FailurePredictStatus");
            using var results = searcher.Get();
            var devices = new List<SmartDiskStatus>();
            var anyPredFail = false;

            foreach (ManagementObject mo in results)
            {
                var predictFailure = GetBool(mo, "PredictFailure");
                var status = predictFailure == true ? "Pred Fail" : "OK";
                if (predictFailure == true)
                {
                    anyPredFail = true;
                }

                devices.Add(new SmartDiskStatus
                {
                    InstanceName = GetString(mo, "InstanceName"),
                    PredictFailure = predictFailure,
                    Status = status,
                });
            }

            if (devices.Count == 0)
            {
                return new SmartHealthInfo
                {
                    Status = "No disponible",
                    Message = "Driver no expone SMART.",
                };
            }

            return new SmartHealthInfo
            {
                Status = anyPredFail ? "Pred Fail" : "OK",
                Devices = devices.ToArray(),
            };
        }
        catch (UnauthorizedAccessException)
        {
            return new SmartHealthInfo
            {
                Status = "No disponible",
                Message = "Sin permisos.",
            };
        }
        catch (Exception ex)
        {
            return new SmartHealthInfo
            {
                Status = "No disponible",
                Message = ex.Message,
            };
        }
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
    public SmartHealthInfo SmartHealth { get; init; } = new();
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
    public ulong? TotalPhysicalBytes { get; init; }
    public ulong? TotalVisibleBytes { get; init; }
    public ulong? FreePhysicalBytes { get; init; }
    public ulong? UsedPhysicalBytes { get; init; }
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
    public ulong? SizeBytes { get; init; }
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
    public ulong? SizeBytes { get; init; }
    public string? Type { get; init; }
    public bool? Bootable { get; init; }
    public bool? PrimaryPartition { get; init; }
}

internal sealed class LogicalDiskInfo
{
    public string? DeviceId { get; init; }
    public string? FileSystem { get; init; }
    public ulong? SizeBytes { get; init; }
    public ulong? FreeBytes { get; init; }
    public double? UsedPercent { get; init; }
    public uint? DriveType { get; init; }
    public string? VolumeName { get; init; }
}

internal sealed class NetworkInterfaceInfo
{
    public string? Name { get; init; }
    public string? Description { get; init; }
    public string? Type { get; init; }
    public string? Status { get; init; }
    public long? Speed { get; init; }
    public string? MacAddress { get; init; }
    public string[] IpAddresses { get; init; } = Array.Empty<string>();
}

internal sealed class SmartHealthInfo
{
    public string Status { get; init; } = "No disponible";
    public string? Message { get; init; }
    public SmartDiskStatus[]? Devices { get; init; }
}

internal sealed class SmartDiskStatus
{
    public string? InstanceName { get; init; }
    public bool? PredictFailure { get; init; }
    public string? Status { get; init; }
}

internal sealed class CollectionError
{
    public string Section { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;
}

using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace ApprovalAgent.Mock.Services;

public enum CapabilityAvailability
{
    Available,
    Unavailable,
    Unknown
}

public enum ApiVersionSupport
{
    Supported,
    Unsupported,
    Unknown
}

public sealed record WebAuthnCapabilityResult(
    CapabilityAvailability LibraryAvailability,
    CapabilityAvailability ApiAvailability,
    uint? ApiVersion,
    ApiVersionSupport VersionSupport,
    CapabilityAvailability PlatformAuthenticatorAvailability,
    string? Error);

public sealed record WebAuthnReadOnlyCapabilityReport(
    string Label,
    DateTimeOffset DiagnosticTimestampUtc,
    string WindowsBuild,
    string ProcessArchitecture,
    string DllAvailability,
    string ReadOnlyApiAvailability,
    uint? ReportedApiVersion,
    string ApiVersionState,
    string PlatformAuthenticatorCapability,
    string BasicMakeGetVersionGate,
    string PlatformInventoryVersionGate,
    string PlatformDeletionVersionGate,
    string CheckedExports,
    string FeatureGateEvidence,
    string RealCredentialOperation,
    string? DiagnosticErrorCategory)
{
    private const uint BasicApiVersion = 1;
    private const uint PlatformInventoryAndDeletionApiVersion = 4;

    public static WebAuthnReadOnlyCapabilityReport Create(
        WebAuthnCapabilityResult result,
        DateTimeOffset timestampUtc,
        string windowsBuild,
        string processArchitecture)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentException.ThrowIfNullOrWhiteSpace(windowsBuild);
        ArgumentException.ThrowIfNullOrWhiteSpace(processArchitecture);

        return new WebAuthnReadOnlyCapabilityReport(
            "READ-ONLY CAPABILITY REPORT — NO CREDENTIAL OPERATION",
            timestampUtc.ToUniversalTime(),
            windowsBuild,
            processArchitecture,
            result.LibraryAvailability.ToString(),
            result.ApiAvailability.ToString(),
            result.ApiVersion,
            result.ApiVersion is null ? "UNKNOWN" : result.VersionSupport.ToString(),
            result.PlatformAuthenticatorAvailability.ToString(),
            VersionGate(result, BasicApiVersion),
            VersionGate(result, PlatformInventoryAndDeletionApiVersion),
            VersionGate(result, PlatformInventoryAndDeletionApiVersion),
            "WebAuthNGetApiVersionNumber; " +
            "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
            "Version gates are based on the reviewed Windows SDK header map. " +
            "Other feature exports and runtime behavior remain unverified (not probed).",
            "NOT PERFORMED",
            ErrorCategory(result.Error));
    }

    public string ToJson() =>
        JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            WriteIndented = true
        });

    private static string VersionGate(WebAuthnCapabilityResult result, uint minimum)
    {
        if (result.LibraryAvailability == CapabilityAvailability.Unavailable ||
            result.ApiAvailability == CapabilityAvailability.Unavailable)
            return "BLOCKED_API_UNAVAILABLE";
        if (result.LibraryAvailability == CapabilityAvailability.Unknown ||
            result.ApiAvailability == CapabilityAvailability.Unknown ||
            result.ApiVersion is null ||
            result.VersionSupport == ApiVersionSupport.Unknown)
            return "UNKNOWN";
        if (result.ApiVersion.Value < minimum)
            return "UNSUPPORTED_BY_REPORTED_VERSION";
        if (result.VersionSupport != ApiVersionSupport.Supported)
            return "BLOCKED_VERSION_SUPPORT_NOT_CONFIRMED";
        return "VERSION_GATE_MET_EXPORTS_AND_BEHAVIOR_UNVERIFIED";
    }

    private static string? ErrorCategory(string? error)
    {
        if (error is null) return null;
        if (error.Contains("HRESULT", StringComparison.OrdinalIgnoreCase))
            return "NATIVE_QUERY_NON_S_OK";
        if (error.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
            error.Contains("required WebAuthn API function", StringComparison.OrdinalIgnoreCase))
            return "DLL_OR_EXPORT_UNAVAILABLE";
        if (error.Contains("could not determine", StringComparison.OrdinalIgnoreCase))
            return "VERSION_QUERY_FAILED";
        if (error.Contains("could not load", StringComparison.OrdinalIgnoreCase))
            return "NATIVE_LOAD_FAILED";
        if (error.Contains("could not be completed", StringComparison.OrdinalIgnoreCase))
            return "CAPABILITY_QUERY_FAILED";
        return "DIAGNOSTIC_FAILED_DETAILS_REDACTED";
    }
}

public interface IWebAuthnNativeSession : IDisposable
{
    uint GetApiVersionNumber();

    int IsUserVerifyingPlatformAuthenticatorAvailable(out bool available);
}

public sealed record WebAuthnNativeOpenResult(
    CapabilityAvailability LibraryAvailability,
    CapabilityAvailability ApiAvailability,
    IWebAuthnNativeSession? Session,
    string? Error);

public interface IWebAuthnNativeApi
{
    WebAuthnNativeOpenResult Open();
}

public sealed class WindowsWebAuthnCapabilityDiagnosticService
{
    private const uint MinimumSupportedApiVersion = 1;
    private readonly IWebAuthnNativeApi _nativeApi;

    public WindowsWebAuthnCapabilityDiagnosticService(IWebAuthnNativeApi nativeApi)
    {
        _nativeApi = nativeApi ?? throw new ArgumentNullException(nameof(nativeApi));
    }

    public WebAuthnCapabilityResult GetDiagnostics()
    {
        WebAuthnNativeOpenResult opened;
        try
        {
            opened = _nativeApi.Open();
        }
        catch (Exception error)
        {
            return UnknownResult(
                CapabilityAvailability.Unknown,
                CapabilityAvailability.Unknown,
                $"Could not load the Windows WebAuthn API: {Describe(error)}");
        }

        if (opened is null)
        {
            return UnknownResult(CapabilityAvailability.Unknown,
                CapabilityAvailability.Unknown, "Native API returned no diagnostic result.");
        }

        if (opened.Session is null ||
            opened.ApiAvailability != CapabilityAvailability.Available)
        {
            return UnknownResult(
                opened.LibraryAvailability,
                opened.ApiAvailability,
                opened.Error ?? "The required WebAuthn API functions are unavailable.");
        }

        using var session = opened.Session;

        uint apiVersion;
        try
        {
            apiVersion = session.GetApiVersionNumber();
        }
        catch (Exception error)
        {
            return UnknownResult(
                opened.LibraryAvailability,
                CapabilityAvailability.Available,
                $"Could not determine the WebAuthn API version: {Describe(error)}");
        }

        if (apiVersion < MinimumSupportedApiVersion)
        {
            return new WebAuthnCapabilityResult(
                opened.LibraryAvailability,
                CapabilityAvailability.Available,
                apiVersion,
                ApiVersionSupport.Unsupported,
                CapabilityAvailability.Unknown,
                $"WebAuthn API version {apiVersion} is below the supported minimum " +
                $"{MinimumSupportedApiVersion}.");
        }

        try
        {
            var hresult =
                session.IsUserVerifyingPlatformAuthenticatorAvailable(out var available);
            if (hresult != 0)
            {
                return new WebAuthnCapabilityResult(
                    opened.LibraryAvailability,
                    CapabilityAvailability.Available,
                    apiVersion,
                    ApiVersionSupport.Supported,
                    CapabilityAvailability.Unknown,
                    $"The platform-authenticator query failed with HRESULT " +
                    $"0x{unchecked((uint)hresult):X8}.");
            }

            return new WebAuthnCapabilityResult(
                opened.LibraryAvailability,
                CapabilityAvailability.Available,
                apiVersion,
                ApiVersionSupport.Supported,
                available
                    ? CapabilityAvailability.Available
                    : CapabilityAvailability.Unavailable,
                null);
        }
        catch (Exception error)
        {
            return new WebAuthnCapabilityResult(
                opened.LibraryAvailability,
                CapabilityAvailability.Available,
                apiVersion,
                ApiVersionSupport.Supported,
                CapabilityAvailability.Unknown,
                $"The platform-authenticator query could not be completed: {Describe(error)}");
        }
    }

    private static WebAuthnCapabilityResult UnknownResult(
        CapabilityAvailability library,
        CapabilityAvailability api,
        string error) =>
        new(
            library,
            api,
            null,
            ApiVersionSupport.Unknown,
            CapabilityAvailability.Unknown,
            error);

    private static string Describe(Exception error) => error.GetType().Name;
}

public sealed class WebAuthnDiagnosticsViewModel : INotifyPropertyChanged
{
    private string _libraryStatus = "Not checked";
    private string _apiStatus = "Not checked";
    private string _versionStatus = "Not checked";
    private string _authenticatorStatus = "Not checked";
    private string _errorStatus = "No diagnostic errors reported.";
    private string _structuredReportJson = "Capability report not available.";

    public event PropertyChangedEventHandler? PropertyChanged;

    public string LibraryStatus
    {
        get => _libraryStatus;
        private set => SetField(ref _libraryStatus, value);
    }

    public string ApiStatus
    {
        get => _apiStatus;
        private set => SetField(ref _apiStatus, value);
    }

    public string VersionStatus
    {
        get => _versionStatus;
        private set => SetField(ref _versionStatus, value);
    }

    public string AuthenticatorStatus
    {
        get => _authenticatorStatus;
        private set => SetField(ref _authenticatorStatus, value);
    }

    public string ErrorStatus
    {
        get => _errorStatus;
        private set => SetField(ref _errorStatus, value);
    }

    public string StructuredReportJson
    {
        get => _structuredReportJson;
        private set => SetField(ref _structuredReportJson, value);
    }

    public void Apply(WebAuthnCapabilityResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        LibraryStatus = result.LibraryAvailability.ToString();
        ApiStatus = result.ApiAvailability.ToString();
        VersionStatus = result.ApiVersion is uint version
            ? $"{result.VersionSupport} (version {version})"
            : result.VersionSupport.ToString();
        AuthenticatorStatus = result.PlatformAuthenticatorAvailability.ToString();
        ErrorStatus = result.Error ?? "No diagnostic errors reported.";
        StructuredReportJson = CreateReport(result);
    }

    public void ApplyFailure()
    {
        LibraryStatus = CapabilityAvailability.Unknown.ToString();
        ApiStatus = CapabilityAvailability.Unknown.ToString();
        VersionStatus = ApiVersionSupport.Unknown.ToString();
        AuthenticatorStatus = CapabilityAvailability.Unknown.ToString();
        ErrorStatus = "Diagnostics could not complete. No approval action was taken.";
        StructuredReportJson = CreateReport(new WebAuthnCapabilityResult(
            CapabilityAvailability.Unknown,
            CapabilityAvailability.Unknown,
            null,
            ApiVersionSupport.Unknown,
            CapabilityAvailability.Unknown,
            "diagnostics_failed"));
    }

    private static string CreateReport(WebAuthnCapabilityResult result) =>
        WebAuthnReadOnlyCapabilityReport.Create(
            result,
            DateTimeOffset.UtcNow,
            Environment.OSVersion.Version.Build.ToString(CultureInfo.InvariantCulture),
            RuntimeInformation.ProcessArchitecture.ToString()).ToJson();

    private void SetField(ref string field, string value,
        [CallerMemberName] string? propertyName = null)
    {
        if (field == value) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public sealed class WindowsWebAuthnNativeApi : IWebAuthnNativeApi
{
    private const string LibraryName = "webauthn.dll";

    public WebAuthnNativeOpenResult Open()
    {
        string path;
        try
        {
            path = Path.Combine(Environment.SystemDirectory, LibraryName);
            if (!File.Exists(path))
            {
                return new WebAuthnNativeOpenResult(
                    CapabilityAvailability.Unavailable,
                    CapabilityAvailability.Unavailable,
                    null,
                    $"{LibraryName} was not found in the Windows system directory.");
            }
        }
        catch (Exception error)
        {
            return new WebAuthnNativeOpenResult(
                CapabilityAvailability.Unknown,
                CapabilityAvailability.Unknown,
                null,
                $"Could not inspect the Windows system directory: {Describe(error)}");
        }

        IntPtr handle;
        try
        {
            if (!NativeLibrary.TryLoad(path, out handle))
            {
                return new WebAuthnNativeOpenResult(
                    CapabilityAvailability.Available,
                    CapabilityAvailability.Unavailable,
                    null,
                    $"{LibraryName} exists but could not be loaded.");
            }
        }
        catch (Exception error)
        {
            return new WebAuthnNativeOpenResult(
                CapabilityAvailability.Available,
                CapabilityAvailability.Unavailable,
                null,
                $"{LibraryName} exists but could not be loaded: {Describe(error)}");
        }

        try
        {
            var versionPointer = NativeLibrary.GetExport(
                handle, "WebAuthNGetApiVersionNumber");
            var availabilityPointer = NativeLibrary.GetExport(
                handle, "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable");
            var session = new NativeSession(
                handle,
                Marshal.GetDelegateForFunctionPointer<GetApiVersionDelegate>(versionPointer),
                Marshal.GetDelegateForFunctionPointer<IsAuthenticatorAvailableDelegate>(
                    availabilityPointer));

            return new WebAuthnNativeOpenResult(
                CapabilityAvailability.Available,
                CapabilityAvailability.Available,
                session,
                null);
        }
        catch (Exception error)
        {
            NativeLibrary.Free(handle);
            return new WebAuthnNativeOpenResult(
                CapabilityAvailability.Available,
                CapabilityAvailability.Unavailable,
                null,
                $"A required WebAuthn API function is unavailable: {Describe(error)}");
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint GetApiVersionDelegate();

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int IsAuthenticatorAvailableDelegate(
        [MarshalAs(UnmanagedType.Bool)] out bool available);

    private sealed class NativeSession : IWebAuthnNativeSession
    {
        private IntPtr _handle;
        private readonly GetApiVersionDelegate _getApiVersion;
        private readonly IsAuthenticatorAvailableDelegate _isAuthenticatorAvailable;

        public NativeSession(
            IntPtr handle,
            GetApiVersionDelegate getApiVersion,
            IsAuthenticatorAvailableDelegate isAuthenticatorAvailable)
        {
            _handle = handle;
            _getApiVersion = getApiVersion;
            _isAuthenticatorAvailable = isAuthenticatorAvailable;
        }

        public uint GetApiVersionNumber() => _getApiVersion();

        public int IsUserVerifyingPlatformAuthenticatorAvailable(out bool available) =>
            _isAuthenticatorAvailable(out available);

        public void Dispose()
        {
            if (_handle == IntPtr.Zero) return;
            NativeLibrary.Free(_handle);
            _handle = IntPtr.Zero;
        }
    }

    private static string Describe(Exception error) => error.GetType().Name;
}

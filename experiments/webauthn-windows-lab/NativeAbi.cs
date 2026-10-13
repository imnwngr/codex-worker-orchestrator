using System.Runtime.InteropServices;

namespace WebAuthn.WindowsLab;

// These are data-only x64 layout snapshots from the installed Windows SDK
// webauthn.h. They are not P/Invoke declarations and cannot call native code.
[StructLayout(LayoutKind.Sequential)]
internal struct AbiRpEntityV1
{
    public uint Version;
    public IntPtr Id;
    public IntPtr Name;
    public IntPtr Icon;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiUserEntityV1
{
    public uint Version;
    public uint IdLength;
    public IntPtr Id;
    public IntPtr Name;
    public IntPtr Icon;
    public IntPtr DisplayName;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiClientDataV1
{
    public uint Version;
    public uint JsonLength;
    public IntPtr Json;
    public IntPtr HashAlgorithm;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiCoseCredentialParameterV1
{
    public uint Version;
    public IntPtr CredentialType;
    public int Algorithm;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiCoseCredentialParameters
{
    public uint Count;
    public IntPtr Parameters;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiCredentialV1
{
    public uint Version;
    public uint IdLength;
    public IntPtr Id;
    public IntPtr CredentialType;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiCredentials
{
    public uint Count;
    public IntPtr Credentials;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiExtension
{
    public IntPtr Identifier;
    public uint Length;
    public IntPtr Value;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiExtensions
{
    public uint Count;
    public IntPtr Extensions;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiMakeCredentialOptionsV1
{
    public uint Version;
    public uint TimeoutMilliseconds;
    public AbiCredentials ExcludeCredentials;
    public AbiExtensions Extensions;
    public uint AuthenticatorAttachment;
    public int RequireResidentKey;
    public uint UserVerificationRequirement;
    public uint AttestationConveyancePreference;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiGetAssertionOptionsV1
{
    public uint Version;
    public uint TimeoutMilliseconds;
    public AbiCredentials Credentials;
    public AbiExtensions Extensions;
    public uint AuthenticatorAttachment;
    public uint UserVerificationRequirement;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiCredentialAttestationV1
{
    public uint Version;
    public IntPtr FormatType;
    public uint AuthenticatorDataLength;
    public IntPtr AuthenticatorData;
    public uint AttestationLength;
    public IntPtr Attestation;
    public uint DecodeType;
    public IntPtr DecodedAttestation;
    public uint AttestationObjectLength;
    public IntPtr AttestationObject;
    public uint CredentialIdLength;
    public IntPtr CredentialId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct AbiAssertionV1
{
    public uint Version;
    public uint AuthenticatorDataLength;
    public IntPtr AuthenticatorData;
    public uint SignatureLength;
    public IntPtr Signature;
    public AbiCredentialV1 Credential;
    public uint UserIdLength;
    public IntPtr UserId;
}

internal readonly record struct NativeApiProfile(
    uint ApiVersion,
    uint MakeCredentialOptionsVersion,
    uint GetAssertionOptionsVersion,
    uint AttestationVersion,
    uint AssertionVersion)
{
    public const uint FirstApiVersion = 1;
    public const uint LastHeaderApiVersion = 9;

    // This table is copied from the API version comments in the installed SDK
    // header. It describes that header's version contract, not a DLL query.
    public static NativeApiProfile ForHeaderVersion(uint apiVersion)
    {
        return apiVersion switch
        {
            1 or 2 => new(apiVersion, 3, 4, 3, 1),
            3 => new(apiVersion, 4, 5, 4, 2),
            4 or 5 => new(apiVersion, 5, 6, 4, 3),
            6 => new(apiVersion, 6, 6, 5, 4),
            7 => new(apiVersion, 7, 7, 6, 5),
            8 => new(apiVersion, 8, 8, 7, 5),
            9 => new(apiVersion, 9, 9, 8, 6),
            _ => throw new NotSupportedException(
                $"WebAuthn API version {apiVersion} is not in the inspected header.")
        };
    }

    public bool SupportsStructureVersions(
        uint makeOptions, uint getOptions, uint attestation, uint assertion) =>
        makeOptions == MakeCredentialOptionsVersion &&
        getOptions == GetAssertionOptionsVersion &&
        attestation == AttestationVersion &&
        assertion == AssertionVersion;
}

internal static class NativeAbiContract
{
    // WINAPI is __stdcall in the inspected header. This metadata is not a
    // delegate or callable import.
    public const CallingConvention CallingConvention = System.Runtime.InteropServices.CallingConvention.Winapi;
    public const int S_OK = 0;

    public static bool HResultSucceeded(int result) => result == S_OK;

    public const NativeResultOwnership InputBufferOwnership =
        NativeResultOwnership.CallerOwnedForCall;
    public const NativeResultOwnership ReturnedResultOwnership =
        NativeResultOwnership.ApiOwnedUntilMatchingFreeFunction;
}

internal enum NativeResultOwnership
{
    CallerOwnedForCall,
    ApiOwnedUntilMatchingFreeFunction
}

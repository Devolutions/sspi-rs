param(
    [Parameter(Mandatory = $true)]
    [string] $OutputPath,

    [switch] $AllowMissingCredentials
)

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'PKU2U Windows fixtures can only be captured on Windows.'
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NativeSspi
{
    [StructLayout(LayoutKind.Sequential)]
    public struct SecPkgInfo
    {
        public uint Capabilities;
        public ushort Version;
        public ushort RpcId;
        public uint MaxToken;
        public IntPtr Name;
        public IntPtr Comment;
    }

    [DllImport("secur32.dll", CharSet = CharSet.Unicode)]
    private static extern int QuerySecurityPackageInfoW(string packageName, out IntPtr packageInfo);

    [DllImport("secur32.dll")]
    private static extern int FreeContextBuffer(IntPtr contextBuffer);

    public static object QueryPackage(string packageName)
    {
        IntPtr packageInfo;
        int status = QuerySecurityPackageInfoW(packageName, out packageInfo);
        if (status != 0)
        {
            throw new InvalidOperationException(
                string.Format("QuerySecurityPackageInfoW failed with 0x{0:X8}", status)
            );
        }

        try
        {
            SecPkgInfo info = Marshal.PtrToStructure<SecPkgInfo>(packageInfo);
            return new
            {
                capabilities = info.Capabilities,
                version = info.Version,
                rpcId = info.RpcId,
                maxToken = info.MaxToken,
                name = Marshal.PtrToStringUni(info.Name),
                comment = Marshal.PtrToStringUni(info.Comment),
            };
        }
        finally
        {
            FreeContextBuffer(packageInfo);
        }
    }
}
'@

$pku2uDll = Get-Item -LiteralPath "$env:WINDIR\System32\pku2u.dll"
$package = [NativeSspi]::QueryPackage('pku2u')
$credentials = @(
    Get-ChildItem Cert:\CurrentUser\My |
        Where-Object {
            $_.HasPrivateKey -and
            ($_.Issuer -like '*MS-Organization-P2P-Access*')
        } |
        ForEach-Object {
            [ordered]@{
                subject = $_.Subject
                issuer = $_.Issuer
                thumbprint = $_.Thumbprint
                notAfter = $_.NotAfter.ToUniversalTime().ToString('O')
            }
        }
)

if ($credentials.Count -eq 0 -and -not $AllowMissingCredentials) {
    throw 'No CurrentUser\My certificate with an MS-Organization-P2P-Access issuer and private key was found.'
}

$fixture = [ordered]@{
    schemaVersion = 1
    capturedAt = (Get-Date).ToUniversalTime().ToString('O')
    operatingSystem = [Environment]::OSVersion.VersionString
    binary = [ordered]@{
        path = $pku2uDll.FullName
        fileVersion = $pku2uDll.VersionInfo.FileVersion
        sha256 = (Get-FileHash -LiteralPath $pku2uDll.FullName -Algorithm SHA256).Hash
    }
    package = $package
    credentialsAvailable = $credentials.Count -gt 0
    credentials = $credentials
    handshakeCaptureReady = $credentials.Count -gt 0
}

$parent = Split-Path -Parent $OutputPath
if ($parent) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$json = $fixture | ConvertTo-Json -Depth 8
$utf8NoBom = New-Object System.Text.UTF8Encoding
[System.IO.File]::WriteAllText($OutputPath, $json, $utf8NoBom)

Write-Host "PKU2U fixture metadata written to $OutputPath"
if ($credentials.Count -eq 0) {
    Write-Warning 'Package metadata was captured, but wire capture requires an Azure AD P2P certificate with a private key.'
}

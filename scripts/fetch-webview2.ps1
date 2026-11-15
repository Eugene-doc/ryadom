param(
 [string]$Version = '1.0.4314.35',
 [string]$Sha256 = '90778DEB1B77E36292828B4B5833C9255C27533F40E0DDD55891AE718944EDC4'
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Dir = Join-Path $Root '.tools\webview2'
$Package = Join-Path $Dir 'package'
$Archive = Join-Path $Dir 'webview2.nupkg'
$Core = Join-Path $Package 'lib\net462\Microsoft.Web.WebView2.Core.dll'
if (Test-Path -LiteralPath $Core) { Write-Host "WebView2 SDK already present: $Version"; exit 0 }
New-Item -ItemType Directory -Path $Dir -Force | Out-Null
$Url = "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$Version/microsoft.web.webview2.$Version.nupkg"
Write-Host "Downloading WebView2 SDK $Version"
Invoke-WebRequest -Uri $Url -OutFile $Archive -UseBasicParsing -TimeoutSec 300
$Actual = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
if ($Actual -ne $Sha256) { Remove-Item -LiteralPath $Archive -Force -ErrorAction SilentlyContinue; throw "WebView2 SDK SHA-256 mismatch: $Actual" }
Expand-Archive -LiteralPath $Archive -DestinationPath $Package -Force
if (-not (Test-Path -LiteralPath $Core)) { throw 'WebView2 SDK extraction failed' }
Write-Host "WebView2 SDK ready: $Version"

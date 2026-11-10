param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'dist\DnsLookup.exe')
)

$ErrorActionPreference = 'Stop'
$frameworkRoot = Join-Path $env:WINDIR 'Microsoft.NET'
$compiler = @('Framework64', 'Framework') | ForEach-Object {
    Join-Path $frameworkRoot "$_\v4.0.30319\csc.exe"
} | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1

if (-not $compiler) { throw 'The .NET Framework C# compiler is missing.' }

$destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
$sources = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Filter '*.cs' -File |
    Sort-Object Name | ForEach-Object { $_.FullName }

& $compiler /nologo /warnaserror+ /codepage:65001 /optimize+ /target:winexe /platform:anycpu `
    "/out:$destination" /r:System.Windows.Forms.dll /r:System.Drawing.dll @sources
if ($LASTEXITCODE -ne 0) { throw "The build failed with exit code $LASTEXITCODE." }
Write-Output $destination

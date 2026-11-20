# SPDX-License-Identifier: GPL-3.0-or-later
# Stages the third-party payload of the Windows package from each project's own download: Zig, the embeddable Python with the lz4
# and capstone wheels, the AMD-signed FSR 3 DLLs, the NVIDIA-signed Streamline DLLs, and their licence texts. Every download is
# checked against the SHA-256 pinned below (the hash each project publishes: ziglang.org's index, python.org, PyPI, the Streamline
# release; the FSR files are fetched at the tag's commit). Nothing comes from an earlier Recompia release. make-release.ps1 takes
# -Out as its -Tools. Downloads are kept in -Cache; a cached file is checked again like a fresh one.
#   pwsh game-build\scripts\fetch-windows-tools.ps1 -Cache work\tools-dl -Out work\tools
# Bump together with launcher/src-tauri/src/host.rs (the Linux and macOS pins) and game-build/release_b/BUNDLED_TOOLS.txt.
param(
    [Parameter(Mandatory)][string]$Cache,
    [Parameter(Mandatory)][string]$Out
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$fsr = 'https://raw.githubusercontent.com/GPUOpen-LibrariesAndSDKs/FidelityFX-SDK/7539ae8b6568ad29ed78a753404351daf3b5cca7'   # tag v2.4.0
$pins = [ordered]@{
    'zig-x86_64-windows-0.17.0.zip'          = @('https://ziglang.org/download/0.17.0/zig-x86_64-windows-0.17.0.zip',
                                                 'b5663f69581dcf391293fbf16c06cb80d81d806545ce618b4d0bab7f0eb8c428')
    'python-3.13.15-embed-amd64.zip'         = @('https://www.python.org/ftp/python/3.13.15/python-3.13.15-embed-amd64.zip',
                                                 'd1f04d990aee1253d8569e8e5104e30fa9f5fa830899f14843448872d936a2cf')
    'lz4-4.4.5-cp313-cp313-win_amd64.whl'    = @('https://files.pythonhosted.org/packages/18/e0/f06028aea741bbecb2a7e9648f4643235279a770c7ffaf70bd4860c73661/lz4-4.4.5-cp313-cp313-win_amd64.whl',
                                                 'da68497f78953017deb20edff0dba95641cc86e7423dfadf7c0264e1ac60dc22')
    'capstone-5.0.9-py3-none-win_amd64.whl'  = @('https://files.pythonhosted.org/packages/50/e6/6f06fdb6a9ed32b2f7cd9c036b92d5324112c3ef7080f2c71efc367d40dd/capstone-5.0.9-py3-none-win_amd64.whl',
                                                 '732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0')
    'amd_fidelityfx_loader_vk.dll'           = @("$fsr/Kits/FidelityFX/signedbin/amd_fidelityfx_loader_vk.dll",
                                                 '38a56a01fb3565c0757d9f5c1e4e69de4b65e5f2e5769b323b200dc1f142bab9')
    'amd_fidelityfx_upscaler_vk.dll'         = @("$fsr/Kits/FidelityFX/signedbin/amd_fidelityfx_upscaler_vk.dll",
                                                 '4a7e895af6e0b615d40a84d59eb8c2b1054ad91cdd0c739567940270d51bdab7')
    'FidelityFX-SDK-license.md'              = @("$fsr/Kits/FidelityFX/docs/license.md",
                                                 '32357259b965d6a8001e9e508ba60eda6034027c5923a7d226ffbaff813c2bfb')
    'streamline-sdk-v2.14.16.zip'            = @('https://github.com/NVIDIA-RTX/Streamline/releases/download/v2.14.16/streamline-sdk-v2.14.16.zip',
                                                 '32041e51db0cab709a271b72a352281b690c2abbd669a827809401a5dd23956b')
}

function Get-Pinned([string]$name) {
    $url, $sha = $pins[$name]
    $file = Join-Path $Cache $name
    if (Test-Path $file) {
        if ((Get-FileHash $file -Algorithm SHA256).Hash.ToLower() -eq $sha) {
            Write-Host "fetch-windows-tools.cache.hit $name"
            return $file
        }
        Write-Host "fetch-windows-tools.cache.stale $name (hash differs, downloading again)"
        Remove-Item -Force $file
    } else {
        Write-Host "fetch-windows-tools.cache.miss $name"
    }
    curl.exe -fL --retry 5 --retry-delay 15 --retry-all-errors -o $file $url
    if ($LASTEXITCODE) { throw "download failed: $url" }
    $got = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $sha) {
        Remove-Item -Force $file
        throw "SHA-256 mismatch for $name from $url`: expected $sha, got $got"
    }
    Write-Host "fetch-windows-tools.download.ok $name"
    return $file
}

# Extracts the entries of $zip whose path (after $prefix) $keep accepts into $dest. Returns the number of files written.
function Expand-Filtered([string]$zip, [string]$prefix, [string]$dest, [scriptblock]$keep) {
    $root = [IO.Path]::GetFullPath($dest)
    New-Item -ItemType Directory -Force $root | Out-Null
    $n = 0
    $z = [IO.Compression.ZipFile]::OpenRead($zip)
    try {
        foreach ($e in $z.Entries) {
            if ($e.FullName.EndsWith('/') -or -not $e.FullName.StartsWith($prefix)) { continue }
            $rel = $e.FullName.Substring($prefix.Length)
            if (-not (& $keep $rel)) { continue }
            $target = [IO.Path]::GetFullPath((Join-Path $root $rel))
            if (-not $target.StartsWith($root + [IO.Path]::DirectorySeparatorChar)) { throw "entry outside the target folder: $($e.FullName)" }
            New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $target, $true)
            $n++
        }
    } finally {
        $z.Dispose()
    }
    if ($n -eq 0) { throw "nothing extracted from $zip under '$prefix'" }
    return $n
}

New-Item -ItemType Directory -Force $Cache | Out-Null
if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
$lic = Join-Path $Out 'licenses'
New-Item -ItemType Directory -Force $lic | Out-Null

# Zig: the Windows toolchain pkp_build.py links pkp.exe with. Only what an x86_64-windows-gnu link needs is kept: no docs, no
# build-web/fuzzer/init/tsan sources, and of lib/libc only the mingw CRT and its headers.
$zigKeep = {
    param($rel)
    if ($rel -eq 'lib/fuzzer.zig') { return $false }
    foreach ($p in 'doc/', 'lib/build-web/', 'lib/docs/', 'lib/init/', 'lib/libtsan/') { if ($rel.StartsWith($p)) { return $false } }
    if ($rel.StartsWith('lib/libc/')) { return $rel.StartsWith('lib/libc/mingw/') -or $rel.StartsWith('lib/libc/include/any-windows-any/') }
    return $true
}
$zigZip = Get-Pinned 'zig-x86_64-windows-0.17.0.zip'
$zigDir = Join-Path $Out 'tools\build\zig'
$n = Expand-Filtered $zigZip 'zig-x86_64-windows-0.17.0/' $zigDir $zigKeep
Write-Host "fetch-windows-tools.zig files=$n"
Copy-Item (Join-Path $zigDir 'LICENSE') (Join-Path $lic 'LICENSE.zig.MIT.txt')
$v = & (Join-Path $zigDir 'zig.exe') version
if ($LASTEXITCODE -or $v -ne '0.17.0') { throw "the staged zig.exe does not run as 0.17.0 (got '$v')" }

# Python: the embeddable package, site-packages switched on in its ._pth, and the two wheels unpacked into it.
$pyDir = Join-Path $Out 'tools\python'
$n = Expand-Filtered (Get-Pinned 'python-3.13.15-embed-amd64.zip') '' $pyDir { $true }
Write-Host "fetch-windows-tools.python files=$n"
[IO.File]::WriteAllText((Join-Path $pyDir 'python313._pth'), "python313.zip`n.`nLib\site-packages`n")
$site = Join-Path $pyDir 'Lib\site-packages'
foreach ($w in 'lz4-4.4.5-cp313-cp313-win_amd64.whl', 'capstone-5.0.9-py3-none-win_amd64.whl') {
    $n = Expand-Filtered (Get-Pinned $w) '' $site { $true }
    Write-Host "fetch-windows-tools.wheel $w files=$n"
}
Copy-Item (Join-Path $pyDir 'LICENSE.txt') (Join-Path $lic 'LICENSE.Python.PSF.txt')
& (Join-Path $pyDir 'python.exe') -I -B -c 'import lz4.block, capstone'
if ($LASTEXITCODE) { throw 'the staged Python cannot import lz4.block and capstone' }

# FSR 3: the two AMD-signed Vulkan DLLs the runtime loads from upscalers\fsr3, and the SDK licence.
$fsrDir = Join-Path $Out 'upscalers\fsr3'
New-Item -ItemType Directory -Force $fsrDir | Out-Null
foreach ($d in 'amd_fidelityfx_loader_vk.dll', 'amd_fidelityfx_upscaler_vk.dll') { Copy-Item (Get-Pinned $d) (Join-Path $fsrDir $d) }
Copy-Item (Get-Pinned 'FidelityFX-SDK-license.md') (Join-Path $lic 'LICENSE.FidelityFX-SDK-v2.4.0.txt')

# Streamline: the three NVIDIA-signed release DLLs the runtime loads from upscalers\streamline, its licence, its third-party
# notices, and the NVIDIA RTX SDKs licence BUNDLED_TOOLS.txt points to for nvngx_dlss.dll (which the package does not carry).
$slZip = Get-Pinned 'streamline-sdk-v2.14.16.zip'
$slDlls = 'bin/x64/sl.common.dll', 'bin/x64/sl.dlss.dll', 'bin/x64/sl.interposer.dll'
$n = Expand-Filtered $slZip 'bin/x64/' (Join-Path $Out 'upscalers\streamline') { param($rel) $slDlls -contains "bin/x64/$rel" }
if ($n -ne 3) { throw "expected 3 Streamline DLLs, extracted $n" }
$slText = @{ 'license.txt' = 'LICENSE.Streamline.MIT.txt'; '3rd-party-licenses.md' = 'NOTICE.Streamline-3rd-party.md'; 'bin/x64/nvngx_dlss.license.txt' = 'LICENSE.NVIDIA-RTX-SDKs.txt' }
$tmp = Join-Path $Cache 'streamline-text'
$null = Expand-Filtered $slZip '' $tmp { param($rel) $slText.ContainsKey($rel) }
foreach ($k in $slText.Keys) { Copy-Item (Join-Path $tmp $k) (Join-Path $lic $slText[$k]) }
Remove-Item -Recurse -Force $tmp

Write-Host "fetch-windows-tools.done $Out"

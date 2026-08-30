# Assemble the portable package.
#
# A portable copy is just the executable plus an empty `Jetstream Data` folder:
# that folder's presence is what switches the app out of per-user mode, so the
# package needs no installer, no registry entry and no marker file to explain.
#
#   pwsh scripts/portable.ps1
#
# Produces target/portable/Jetstream-<version>-portable.zip

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# Read the version from the app's manifest rather than repeating it here, so the
# zip name can never disagree with what the app reports about itself.
$conf = Get-Content "$root\apps\desktop\src-tauri\tauri.conf.json" -Raw | ConvertFrom-Json
$version = $conf.version

Write-Host "Building Jetstream $version (release)..."
Push-Location "$root\apps\desktop"
try {
    # The bundlers are skipped: a portable package is the bare executable, and
    # building the installers as well would double the packaging time.
    npx tauri build --no-bundle
    if ($LASTEXITCODE -ne 0) { throw "the release build failed" }
} finally {
    Pop-Location
}

$exe = "$root\target\release\jetstream.exe"
if (-not (Test-Path $exe)) { throw "expected $exe to exist after the build" }

$stage = "$root\target\portable\Jetstream-$version-portable"
if (Test-Path $stage) {
    try {
        Remove-Item -Recurse -Force $stage -ErrorAction Stop
    } catch {
        # Almost always a copy of the previous package still running, which holds
        # a lock on its own executable. Say so, rather than reporting a bare
        # access-denied that looks like a permissions problem.
        throw "Could not clear $stage. If a portable Jetstream is running from " +
              "there, quit it (tray icon -> Quit Jetstream) and run this again. " +
              "Underlying error: $($_.Exception.Message)"
    }
}
$dataDir = New-Item -ItemType Directory -Path "$stage\Jetstream Data" -Force
Copy-Item $exe "$stage\Jetstream.exe"

# The folder has to survive zipping, and a user who finds it deserves to know
# what it is before deciding to delete it.
@'
This folder is what makes Jetstream portable.

Everything this copy of Jetstream knows lives in here: its device identity, the
devices it trusts, its settings and its transfer history. Nothing is written to
the computer outside this folder.

Keep it next to Jetstream.exe. Delete it and Jetstream reverts to storing state
per-user on whatever computer it runs on, like an installed copy -- and this
device gets a new identity, so anything that had paired with it will ask again.

One thing to know: the private key in here is NOT encrypted to a Windows
account, because it has to work on any computer you plug this into. Treat the
drive as you would an unencrypted SSH key -- whoever holds it can act as this
device. An installed copy does not have this tradeoff.
'@ | Set-Content -Path "$dataDir\README.txt" -Encoding utf8

@"
Jetstream $version -- portable

Run Jetstream.exe. There is nothing to install.

Windows will ask whether to allow it through the firewall, or Jetstream will
offer an "Allow through firewall" button on its main screen. Without that rule
this copy can still send and will still appear on other devices, but nothing can
arrive. The rule is tied to the path this program is sitting at, so if you move
the folder or the drive letter changes, allow it again.

Two settings are unavailable in a portable copy -- start-with-Windows, and the
Explorer "Send to" entry. Both would leave something on the host computer that
points at this folder and would break the moment you unplug it.

To move this device to another computer, take the whole folder including
"Jetstream Data". Its identity travels with it, so devices that trusted it still
will.

Requires Windows 10 or later. WebView2 is already present on Windows 11 and on
up-to-date Windows 10; if Jetstream reports it missing, install the Microsoft
Edge WebView2 Runtime.
"@ | Set-Content -Path "$stage\README.txt" -Encoding utf8

$zip = "$root\target\portable\Jetstream-$version-portable.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path "$stage\*" -DestinationPath $zip

$size = (Get-Item $zip).Length / 1MB
Write-Host ("`nPortable package: {0} ({1:N1} MB)" -f $zip, $size)
Write-Host "Unzipped folder:  $stage"

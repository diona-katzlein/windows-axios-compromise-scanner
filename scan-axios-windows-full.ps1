param(
    [string]$ScanRoot = $HOME
)

$ErrorActionPreference = 'SilentlyContinue'
$foundIssues = 0

function Banner {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Axios / sfrclak Windows Scanner" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Host:   $env:COMPUTERNAME"
    Write-Host "User:   $env:USERNAME"
    Write-Host "ScanRoot: $ScanRoot"
    Write-Host "Date:   $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"
    Write-Host ""
}

function Section($msg) {
    Write-Host ""
    Write-Host "[*] $msg" -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor Cyan
}

function Found($msg) {
    Write-Host "[!!!] $msg" -ForegroundColor Red
    $script:foundIssues++
}

function Warn($msg) {
    Write-Host "[!] $msg" -ForegroundColor Yellow
}

function Safe($msg) {
    Write-Host "[OK] $msg" -ForegroundColor Green
}

function Info($msg) {
    Write-Host "    $msg"
}

Banner

# =====================================================================
# 1. C2 connections — sfrclak.com
# =====================================================================
Section "Checking for active connections to C2 (sfrclak.com)"

$domain = "sfrclak.com"
$c2IPs = @()

try {
    $dns = Resolve-DnsName -Name $domain -ErrorAction SilentlyContinue
    if ($dns) {
        $c2IPs = $dns | Where-Object { $_.Type -eq "A" } | Select-Object -ExpandProperty IPAddress
        if ($c2IPs.Count -gt 0) {
            Info "C2 domain resolves to:"
            $c2IPs | ForEach-Object { Info "  $_" }
        }
    }
} catch {}

$activeHit = $false

if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conns = Get-NetTCPConnection
    foreach ($ip in $c2IPs) {
        $hits = $conns | Where-Object { $_.RemoteAddress -eq $ip }
        if ($hits) {
            $activeHit = $true
            Found "Active TCP connection to $domain ($ip)"
            $hits | Format-Table -AutoSize | Out-String | ForEach-Object { "    $_" }
        }
    }
}

if (-not $activeHit) {
    $netstat = netstat -ano | Select-String $domain
    if ($netstat) {
        $activeHit = $true
        Found "netstat shows connection entries containing '$domain'"
        $netstat | ForEach-Object { "    $_" }
    }
}

if (-not $activeHit) {
    Safe "No active C2 connections detected"
}

# =====================================================================
# 2. Windows IOCs — files on disk
# =====================================================================
Section "Checking Windows filesystem IOCs"

$programData = $env:ProgramData
$tempDir     = $env:TEMP

$paths = @(
    (Join-Path $programData "wt.exe"),
    (Join-Path $tempDir "6202033.vbs"),
    (Join-Path $tempDir "6202033.ps1")
)

foreach ($p in $paths) {
    if (Test-Path $p) {
        Found "Windows IOC file found: $p"
        try {
            $fi = Get-Item $p
            Info ("Size: {0} bytes, LastWrite: {1}" -f $fi.Length, $fi.LastWriteTimeUtc.ToString("u"))
        } catch {}
    }
}

Safe "Windows IOC file check complete"

# =====================================================================
# 3. npm cache — axios / plain-crypto-js
# =====================================================================
Section "Checking npm cache for compromised packages"

if (Get-Command npm -ErrorAction SilentlyContinue) {
    $npmCache = npm config get cache 2>$null
    if (-not $npmCache -or $npmCache -eq "undefined") {
        $npmCache = Join-Path $env:USERPROFILE ".npm"
    }

    Info "npm cache directory: $npmCache"

    if (Test-Path $npmCache) {
        $cacache = Join-Path $npmCache "_cacache"
        if (Test-Path $cacache) {
            $plainHits = Get-ChildItem -Path $cacache -Recurse -Include *.json |
                Select-String -Pattern "plain-crypto-js"

            if ($plainHits) {
                Warn "plain-crypto-js found in npm cache:"
                $plainHits | Select-Object -First 20 | ForEach-Object { "    $($_.Path)" }
            } else {
                Safe "npm cache clean of plain-crypto-js"
            }

            $axiosHits = Get-ChildItem -Path $cacache -Recurse -Include *.json |
                Select-String -Pattern '"axios","version":"1.14.1"','"axios","version":"0.30.4"'

            if ($axiosHits) {
                Warn "Compromised axios versions found in npm cache:"
                $axiosHits | Select-Object -First 20 | ForEach-Object { "    $($_.Path)" }
            } else {
                Safe "No compromised axios versions found in npm cache"
            }
        }
    }
} else {
    Warn "npm not found, skipping npm cache scan"
}

# =====================================================================
# 4. Running processes — suspicious payload indicators
# =====================================================================
Section "Checking running processes for known payload indicators"

$procHit = $false

try {
    $procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine
} catch {
    $procs = Get-Process | Select-Object Id, ProcessName
}

$patterns = @(
    "com.apple.act.mond",
    "ld.py",
    "6202033",
    "sfrclak",
    "wt.exe",
    "plain-crypto-js"
)

foreach ($pat in $patterns) {
    $matches = $procs | Where-Object {
        $_.Name -like "*$pat*" -or
        $_.ProcessName -like "*$pat*" -or
        ($_.CommandLine -and $_.CommandLine -like "*$pat*")
    }

    if ($matches) {
        $procHit = $true
        Found "Suspicious process matching '$pat'"
        $matches | Select-Object -First 10 | ForEach-Object {
            if ($_.CommandLine) {
                "    PID=$($_.ProcessId) Name=$($_.Name) Cmd=$($_.CommandLine)"
            } else {
                "    PID=$($_.Id) Name=$($_.ProcessName)"
            }
        }
    }
}

if (-not $procHit) {
    Safe "No suspicious processes detected"
}

# =====================================================================
# 5. PowerShell history — recent install commands
# =====================================================================
Section "Checking PowerShell history for recent install commands"

$historyPaths = @()

try {
    $psro = Get-PSReadLineOption
    if ($psro -and $psro.HistorySavePath) {
        $historyPaths += $psro.HistorySavePath
    }
} catch {}

$legacyHist = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $legacyHist) {
    $historyPaths += $legacyHist
}

$historyPaths = $historyPaths | Select-Object -Unique

foreach ($hf in $historyPaths) {
    if (Test-Path $hf) {
        Info "History file: $hf"
        $recentInstalls = Get-Content $hf |
            Select-String -Pattern "npm install","npm i ","yarn add","pnpm add","bun add","bun install" |
            Select-Object -Last 20

        if ($recentInstalls) {
            Info "Recent install commands:"
            $recentInstalls | ForEach-Object { "    $($_.Line)" }
        } else {
            Info "No recent install commands found"
        }
    }
}

# =====================================================================
# SUMMARY
# =====================================================================
Write-Host ""
Write-Host "========================================"
Write-Host "  SCAN COMPLETE"
Write-Host "========================================"
Write-Host ""

if ($foundIssues -gt 0) {
    Write-Host "!!  $foundIssues ISSUE(S) FOUND — SYSTEM MAY BE COMPROMISED" -ForegroundColor Red
    Write-Host ""
    Write-Host "Immediate recommendations:"
    Write-Host "  • Disconnect network if C2 or payloads detected"
    Write-Host "  • Remove compromised packages"
    Write-Host "  • Clean npm cache: npm cache clean --force"
    Write-Host "  • Delete IOC files after triage"
    Write-Host "  • Rotate credentials"
    Write-Host "  • Block sfrclak.com at DNS/firewall"
} else {
    Write-Host "No indicators of compromise found." -ForegroundColor Green
}

Write-Host ""
Write-Host "Scanner finished at $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')"

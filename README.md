# AzMigrate Scanner

> **Disclaimer**
>
> This software is provided as **sample code** for illustrative and informational purposes only. It is licensed to you on an **"AS IS" and "AS AVAILABLE" basis, without warranties or conditions of any kind**, either express or implied, including, without limitation, any warranties or conditions of title, non-infringement, merchantability, or fitness for a particular purpose.
>
> **No support, maintenance, updates, or service-level commitments of any kind are provided** in connection with this code. To the maximum extent permitted by applicable law, in no event shall the authors, contributors, or copyright holders be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, loss of data, business interruption, or loss of profits) arising in any way out of the use of, or inability to use, this software, even if advised of the possibility of such damages.
>
> You are solely responsible for evaluating the suitability of this code for your environment, for complying with all applicable laws and policies, and for ensuring that you are duly authorized to scan any networks or systems against which it is run. Use is governed by the terms of the [LICENSE](LICENSE) file included with this repository.

`Test-AzureMigrateDiscovery.ps1` is a PowerShell script that scans an IP range, CIDR block, or list of hosts to verify that servers are reachable on the TCP ports required by the [Azure Migrate](https://learn.microsoft.com/azure/migrate/migrate-support-matrix) appliance for agentless discovery.

For each target it performs:

- ICMP ping
- DNS reverse / forward lookup
- TCP port checks:
  - **Windows**: WinRM (5985 HTTP, 5986 HTTPS), SMB (445), RPC (135), NetBIOS (139)
  - **Linux**: SSH (22)

Results are printed as a table and exported to CSV.

> **Disclaimer:** MIT-licensed and provided "AS IS". Only scan networks you are authorized to scan.

---

## Requirements

- Windows PowerShell 5.1, or PowerShell 7+ (recommended — enables parallel scanning via `-ThrottleLimit`)
- Network reachability from the machine running the script to the targets
- Permission / authorization to scan the target network

Check your version:

```powershell
$PSVersionTable.PSVersion
```

---

## Download from GitHub using PowerShell

Pick **one** of the options below.

### Option 1: Clone with Git (recommended)

```powershell
# Requires git.exe on PATH
cd C:\Tools
git clone https://github.com/maheshbenke/AzMigrate-Scanner.git
cd AzMigrate-Scanner
```

### Option 2: Download a single file with `Invoke-WebRequest`

```powershell
$dest = "$env:USERPROFILE\Downloads\Test-AzureMigrateDiscovery.ps1"
Invoke-WebRequest `
    -Uri 'https://raw.githubusercontent.com/maheshbenke/AzMigrate-Scanner/main/Test-AzureMigrateDiscovery.ps1' `
    -OutFile $dest
```

### Option 3: Download the whole repo as a ZIP

```powershell
$zip = "$env:TEMP\AzMigrate-Scanner.zip"
$out = "C:\Tools\AzMigrate-Scanner"

Invoke-WebRequest `
    -Uri 'https://github.com/maheshbenke/AzMigrate-Scanner/archive/refs/heads/main.zip' `
    -OutFile $zip

Expand-Archive -Path $zip -DestinationPath $out -Force
Remove-Item $zip
```

---

## Unblock the script (first run only)

Files downloaded from the internet are blocked by Windows. Unblock and (optionally) relax the execution policy for the current session:

```powershell
Unblock-File .\Test-AzureMigrateDiscovery.ps1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

---

## Usage

```text
.\Test-AzureMigrateDiscovery.ps1
    [-Cidr <string[]>]            # one or more CIDR blocks
    [-IpRange <string[]>]         # one or more "start-end" ranges
    [-ComputerName <string[]>]    # explicit host/IP list
    [-InputFile <string>]         # file with hosts/IPs/CIDRs/ranges (one per line, # for comments)
    [-OsType Windows|Linux|Both]  # default: Both
    [-OutputCsv <string>]         # default: .\AzureMigrateDiscoveryScan_<timestamp>.csv
    [-TimeoutSeconds <int>]       # per-port TCP timeout, default 2
    [-ThrottleLimit <int>]        # parallel host scans (PS 7+), default 50
    [-IncludeUnreachable]         # also list hosts with no ping and no open ports
    [-LogFile <string>]           # transcript log path, default .\AzureMigrateDiscoveryScan_<timestamp>.log
    [-OutputReport <string>]      # text report path,    default .\AzureMigrateDiscoveryScan_<timestamp>.txt
```

### Examples

Scan a /24 for Windows readiness:

```powershell
.\Test-AzureMigrateDiscovery.ps1 -Cidr 10.0.0.0/24 -OsType Windows
```

Scan multiple CIDRs for both Windows and Linux:

```powershell
.\Test-AzureMigrateDiscovery.ps1 -Cidr 10.0.0.0/27,10.0.1.0/28 -OsType Both
```

Scan an explicit IP range:

```powershell
.\Test-AzureMigrateDiscovery.ps1 -IpRange 10.0.0.10-10.0.0.50
```

Scan an explicit list of hosts and write to a custom CSV:

```powershell
.\Test-AzureMigrateDiscovery.ps1 `
    -ComputerName srv01,srv02,10.0.0.15 `
    -OutputCsv C:\Temp\scan.csv
```

Scan from an input file (mix of hostnames, IPs, CIDRs, ranges):

```powershell
# targets.txt
# 10.0.0.0/28
# 10.0.1.10-10.0.1.20
# server01.contoso.com
.\Test-AzureMigrateDiscovery.ps1 -InputFile .\targets.txt
```

Use more parallelism on PowerShell 7+:

```powershell
pwsh -File .\Test-AzureMigrateDiscovery.ps1 -Cidr 10.0.0.0/22 -ThrottleLimit 100
```

---

## Output

- A formatted table is written to the console.
- A CSV is written to `-OutputCsv` (default: `.\AzureMigrateDiscoveryScan_<timestamp>.csv` in the current directory).
- A human-readable text report is written to `-OutputReport` (default: `.\AzureMigrateDiscoveryScan_<timestamp>.txt`) containing run metadata, parameters, summary metrics, and a formatted results table.
- A transcript log is written to `-LogFile` (default: `.\AzureMigrateDiscoveryScan_<timestamp>.log`) capturing all console output plus timestamped scan milestones (`[yyyy-MM-dd HH:mm:ss] [INFO|WARN|ERROR] ...`).
- The CSV includes per-host ping status, DNS name, and the open/closed state of each tested port — suitable for sharing with the team responsible for firewall and OS configuration before onboarding to Azure Migrate.

---

## License

MIT — see [LICENSE](LICENSE).

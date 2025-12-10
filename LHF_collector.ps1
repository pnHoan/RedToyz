param(
    [switch]$Verbose,
    [string]$OutputFile = "credential_locations.txt"
)

$results = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-Finding {
    param($Category, $Location, $Details, $Action)
    
    $finding = [PSCustomObject]@{
        Timestamp = $timestamp
        Category = $Category
        Location = $Location
        Details = $Details
        NextSteps = $Action
    }
    
    $script:results += $finding
    
    if ($Verbose) {
        Write-Host "[+] $Category" -ForegroundColor Cyan
        Write-Host "    Location: $Location" -ForegroundColor Yellow
        Write-Host "    Details: $Details" -ForegroundColor Gray
        Write-Host "    Next Steps: $Action`n" -ForegroundColor Green
    }
}

Write-Host "Scanning for potential credential storage locations...`n" -ForegroundColor White

# 1. Browser Credential Databases
Write-Host "[*] Checking Browser Credential Stores..." -ForegroundColor Yellow

$browserPaths = @{
    "Chrome" = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    "Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    "Firefox" = "$env:APPDATA\Mozilla\Firefox\Profiles"
    "Brave" = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
    "Opera" = "$env:APPDATA\Opera Software\Opera Stable\Login Data"
}

foreach ($browser in $browserPaths.Keys) {
    $path = $browserPaths[$browser]
    
    if ($browser -eq "Firefox") {
        if (Test-Path $path) {
            $profiles = Get-ChildItem $path -Directory
            foreach ($profile in $profiles) {
                $loginDB = Join-Path $profile.FullName "logins.json"
                $keyDB = Join-Path $profile.FullName "key4.db"
                if (Test-Path $loginDB) {
                    Write-Finding -Category "Browser Credentials" `
                        -Location $loginDB `
                        -Details "Firefox login database (encrypted)" `
                        -Action "Manual extraction with tools like firefox_decrypt.py"
                }
                if (Test-Path $keyDB) {
                    Write-Finding -Category "Browser Encryption Key" `
                        -Location $keyDB `
                        -Details "Firefox master key database" `
                        -Action "Required for decrypting logins.json"
                }
            }
        }
    } else {
        if (Test-Path $path) {
            Write-Finding -Category "Browser Credentials" `
                -Location $path `
                -Details "$browser login database (DPAPI encrypted)" `
                -Action "Manual extraction with SharpChrome/Mimikatz or manual DPAPI decryption"
        }
    }
}

# 2. Windows Credential Manager
Write-Host "[*] Checking Windows Credential Manager..." -ForegroundColor Yellow

try {
    $creds = cmdkey /list 2>$null
    if ($creds) {
        $credCount = ($creds | Select-String "Target:").Count
        Write-Finding -Category "Windows Credential Manager" `
            -Location "Control Panel\User Accounts\Credential Manager" `
            -Details "Found $credCount stored credentials" `
            -Action "Use 'cmdkey /list' or 'vaultcmd /listcreds:Windows Credentials' | Manual DPAPI decryption with Mimikatz"
    }
} catch {}

# 3. Saved RDP Connections
Write-Host "[*] Checking RDP Saved Connections..." -ForegroundColor Yellow

$rdpPaths = @(
    "HKCU:\Software\Microsoft\Terminal Server Client\Servers",
    "HKCU:\Software\Microsoft\Terminal Server Client\Default"
)

foreach ($rdpPath in $rdpPaths) {
    if (Test-Path $rdpPath) {
        try {
            $servers = Get-ChildItem $rdpPath -ErrorAction SilentlyContinue
            foreach ($server in $servers) {
                Write-Finding -Category "RDP Connection History" `
                    -Location $server.PSPath `
                    -Details "Saved RDP connection to: $($server.PSChildName)" `
                    -Action "Check for saved credentials in Credential Manager"
            }
        } catch {}
    }
}

# 4. PowerShell History
Write-Host "[*] Checking PowerShell Command History..." -ForegroundColor Yellow

$psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHistory) {
    $size = (Get-Item $psHistory).Length
    Write-Finding -Category "PowerShell History" `
        -Location $psHistory `
        -Details "Command history file exists ($size bytes)" `
        -Action "Review manually: type $psHistory | Select-String password,user,credential"
}

# 5. IIS Configuration Files
Write-Host "[*] Checking IIS Configuration..." -ForegroundColor Yellow

$iisConfig = "C:\Windows\System32\inetsrv\config\applicationHost.config"
if (Test-Path $iisConfig) {
    Write-Finding -Category "IIS Configuration" `
        -Location $iisConfig `
        -Details "Contains application pool identities and connection strings" `
        -Action "Review manually for <applicationPools> and <connectionStrings>"
}

# 6. Web Configuration Files
Write-Host "[*] Checking Web Application Configs..." -ForegroundColor Yellow

$webConfigPaths = @(
    "C:\inetpub\wwwroot\web.config",
    "C:\xampp\htdocs\web.config"
)

foreach ($path in $webConfigPaths) {
    if (Test-Path $path) {
        Write-Finding -Category "Web Application Config" `
            -Location $path `
            -Details "May contain database connection strings" `
            -Action "Review manually for <connectionStrings> and <appSettings>"
    }
}

# 7. Configuration Files in Common Locations
Write-Host "[*] Checking Common Config File Locations..." -ForegroundColor Yellow

$configSearchPaths = @(
    @{Path="C:\"; Pattern="*.config"; Depth=2},
    @{Path="C:\inetpub"; Pattern="web.config"; Depth=3},
    @{Path="$env:USERPROFILE"; Pattern="*.xml"; Depth=2}
)

foreach ($search in $configSearchPaths) {
    if (Test-Path $search.Path) {
        try {
            $configs = Get-ChildItem -Path $search.Path -Filter $search.Pattern -Recurse -Depth $search.Depth -ErrorAction SilentlyContinue -File
            foreach ($config in $configs | Select-Object -First 10) {
                Write-Finding -Category "Configuration File" `
                    -Location $config.FullName `
                    -Details "Potential config file with credentials" `
                    -Action "Review manually for passwords, keys, connection strings"
            }
        } catch {}
    }
}

# 8. Registry Auto-Logon
Write-Host "[*] Checking Registry Auto-Logon..." -ForegroundColor Yellow

$autoLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
try {
    $autoLogon = Get-ItemProperty -Path $autoLogonPath -ErrorAction SilentlyContinue
    if ($autoLogon.AutoAdminLogon -eq "1") {
        Write-Finding -Category "Registry Auto-Logon" `
            -Location $autoLogonPath `
            -Details "Auto-logon is enabled" `
            -Action "Check DefaultUserName, DefaultPassword, DefaultDomainName values"
    }
} catch {}

# 9. SSH Keys
Write-Host "[*] Checking SSH Keys..." -ForegroundColor Yellow

$sshPath = "$env:USERPROFILE\.ssh"
if (Test-Path $sshPath) {
    $sshFiles = Get-ChildItem $sshPath -File
    foreach ($file in $sshFiles) {
        Write-Finding -Category "SSH Keys" `
            -Location $file.FullName `
            -Details "SSH key or configuration file" `
            -Action "Review private keys (id_rsa, id_ecdsa, id_ed25519) and config file"
    }
}

# 10. PuTTY Sessions
Write-Host "[*] Checking PuTTY Sessions..." -ForegroundColor Yellow

$puttyPath = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
if (Test-Path $puttyPath) {
    try {
        $sessions = Get-ChildItem $puttyPath
        foreach ($session in $sessions) {
            Write-Finding -Category "PuTTY Session" `
                -Location $session.PSPath `
                -Details "Saved PuTTY session: $($session.PSChildName)" `
                -Action "Check for ProxyPassword value or extract with PuTTY tools"
        }
    } catch {}
}

# 11. Git Credentials
Write-Host "[*] Checking Git Credentials..." -ForegroundColor Yellow

$gitConfig = "$env:USERPROFILE\.gitconfig"
$gitCredentials = "$env:USERPROFILE\.git-credentials"

if (Test-Path $gitConfig) {
    Write-Finding -Category "Git Configuration" `
        -Location $gitConfig `
        -Details "Git config file may contain credentials or helpers" `
        -Action "Review manually for credential helpers and stored credentials"
}

if (Test-Path $gitCredentials) {
    Write-Finding -Category "Git Credentials Store" `
        -Location $gitCredentials `
        -Details "Git credentials file (plaintext)" `
        -Action "Review manually: type $gitCredentials"
}

# 12. Recent Files with Sensitive Names
Write-Host "[*] Checking Recent Files..." -ForegroundColor Yellow

$sensitivePatterns = @("*password*", "*credential*", "*secret*", "*key*")
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"

if (Test-Path $recentPath) {
    foreach ($pattern in $sensitivePatterns) {
        try {
            $files = Get-ChildItem $recentPath -Filter "$pattern.lnk" -ErrorAction SilentlyContinue
            foreach ($file in $files | Select-Object -First 5) {
                Write-Finding -Category "Recent File" `
                    -Location $file.FullName `
                    -Details "Recently accessed file with sensitive name" `
                    -Action "Follow shortcut to find actual file location"
            }
        } catch {}
    }
}

# 13. Database Files
Write-Host "[*] Checking Database Files..." -ForegroundColor Yellow

$dbPatterns = @("*.db", "*.sqlite", "*.mdb", "*.accdb")
$searchPaths = @("C:\", "$env:USERPROFILE")

foreach ($searchPath in $searchPaths) {
    foreach ($pattern in $dbPatterns) {
        try {
            $dbs = Get-ChildItem -Path $searchPath -Filter $pattern -Recurse -Depth 2 -ErrorAction SilentlyContinue -File
            foreach ($db in $dbs | Select-Object -First 5) {
                Write-Finding -Category "Database File" `
                    -Location $db.FullName `
                    -Details "Database file that may contain credentials" `
                    -Action "Extract and analyze with database tools"
            }
        } catch {}
    }
}

# Output Results
Write-Host "`n=== Summary ===" -ForegroundColor Magenta
Write-Host "Total findings: $($results.Count)" -ForegroundColor Green

# Export to file
$results | Export-Csv -Path $OutputFile -NoTypeInformation
Write-Host "`nResults exported to: $OutputFile" -ForegroundColor Cyan

# Display summary table
$results | Format-Table -Property Category, Location -AutoSize
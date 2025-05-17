# WIn11-Home-hardening
PowerShell script to harden Windows for home users and incease privacy

# Run this script as Administrator

# --- Account Policies ---
Write-Host "Setting basic account policies..."
net accounts /minpwlen:10
net user guest /active:no

# --- Disable SMBv1 ---
Write-Host "Disabling SMBv1..."
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

# --- Enable and Harden Windows Firewall ---
Write-Host "Configuring Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# --- Enable Windows Defender and Security Features ---
Write-Host "Enabling Defender settings..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -PUAProtection enable
Set-MpPreference -EnableControlledFolderAccess Enabled

# --- Disable Remote Access Features ---
Write-Host "Disabling Remote Desktop and Remote Assistance..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0

# --- Disable Unused and Risky Services ---
Write-Host "Disabling unnecessary services..."
$services = @(
    "RemoteRegistry",
    "Fax",
    "RetailDemo",
    "XblGameSave",
    "MapsBroker",
    "DiagTrack"
)
foreach ($svc in $services) {
    Get-Service -Name $svc -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
}

# --- Disable AutoRun/AutoPlay ---
Write-Host "Disabling AutoPlay..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWORD -Force

# --- Disable Cortana and Bing Search ---
Write-Host "Disabling Cortana Web Search..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
    -Name "AllowCortana" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" `
    -Name "BingSearchEnabled" -Value 0 -PropertyType DWORD -Force

# --- Disable Activity Tracking and Personalized Ads ---
Write-Host "Disabling activity tracking and ads..."
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" `
    -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" `
    -Name "Enabled" -Value 0 -PropertyType DWORD -Force

# --- Completion Message ---
Write-Host "✅ Home user hardening complete. Please restart your system for all changes to take full effect." -ForegroundColor Green




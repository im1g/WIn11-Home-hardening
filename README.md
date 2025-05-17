# =======================================================================
# ⚠️ WARNING: USE AT YOUR OWN RISK
# -----------------------------------------------------------------------
# This script is intended for **advanced users** who understand Windows
# internals and PowerShell scripting.
#
# It performs security hardening by modifying system settings, registry
# keys, and disabling potentially risky features.
#
# ❗ Potential Risks:
# - Disabling essential Windows services may break functionality.
# - Registry changes can cause instability or boot issues if misapplied.
# - Some features (Defender, Firewall, Updates, OneDrive, Widgets) will
#   be modified or disabled permanently unless reverted.
#
# ✅ Strongly Recommended:
# - Run on a **test system or virtual machine** first.
# - Always **create a System Restore Point** before execution.
# - Review each section to understand its impact before running.
# - Run as **Administrator**.
#
# By using this script, you accept full responsibility for any outcomes.
# =======================================================================


# Run this script as Administrator

# 1. Set Basic Account Policies
Write-Host "1. Setting basic account policies..."
net accounts /minpwlen:10
net user guest /active:no

# 2. Disable SMBv1
Write-Host "2. Disabling SMBv1..."
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart

# 3. Enable and Harden Windows Firewall
Write-Host "3. Configuring Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# 4. Enable Defender and Security Features
Write-Host "4. Enabling Defender settings..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -PUAProtection enable
Set-MpPreference -EnableControlledFolderAccess Enabled

# 5. Disable Remote Access Features
Write-Host "5. Disabling Remote Desktop and Remote Assistance..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0

# 6. Disable Unused and Risky Services
Write-Host "6. Disabling unnecessary services..."
$services = @("RemoteRegistry", "Fax", "RetailDemo", "XblGameSave", "MapsBroker", "DiagTrack")
foreach ($svc in $services) {
    Get-Service -Name $svc -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
}

# 7. Disable AutoRun/AutoPlay
Write-Host "7. Disabling AutoPlay..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 255 -PropertyType DWORD -Force

# 8. Disable Cortana and Bing Search
Write-Host "8. Disabling Cortana Web Search..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" `
    -Name "AllowCortana" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" `
    -Name "BingSearchEnabled" -Value 0 -PropertyType DWORD -Force

# 9. Disable Activity Tracking and Personalized Ads
Write-Host "9. Disabling activity tracking and ads..."
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" `
    -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" `
    -Name "Enabled" -Value 0 -PropertyType DWORD -Force

# 10. Disable IPv6
Write-Host "10. Disabling IPv6..."
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
    -Name "DisabledComponents" -Value 0xFF -PropertyType DWord -Force

# 11. Disable Windows Telemetry (Data Collection)
Write-Host "11. Reducing telemetry..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
    -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force

# 12. Disable Windows Tips & Suggestions
Write-Host "12. Disabling tips and suggestions..."
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
    -Name "SubscribedContent-338389Enabled" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
    -Name "SubscribedContent-310093Enabled" -Value 0 -PropertyType DWORD -Force

# 13. Disable Game Bar and Game DVR
Write-Host "13. Disabling Game Bar..."
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" `
    -Name "AppCaptureEnabled" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\System\GameConfigStore" `
    -Name "GameDVR_Enabled" -Value 0 -PropertyType DWORD -Force

# 14. Disable Remote Assistance Again (Reinforcement)
Write-Host "14. Disabling Remote Assistance (again)..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" `
    -Name "fAllowToGetHelp" -Value 0

# 15. Disable Lock Screen Ads (Spotlight)
Write-Host "15. Disabling lock screen ads..."
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
    -Name "RotatingLockScreenEnabled" -Value 0 -PropertyType DWORD -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
    -Name "RotatingLockScreenOverlayEnabled" -Value 0 -PropertyType DWORD -Force

# 16. Disable Error Reporting
Write-Host "16. Disabling Windows Error Reporting..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" `
    -Name "Disabled" -Value 1 -PropertyType DWORD -Force

# 17. Disable Auto-Reboot after Updates
Write-Host "17. Disabling auto-reboot after updates..."
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "NoAutoRebootWithLoggedOnUsers" -Value 1 -PropertyType DWORD -Force

# 18. Block Third-Party App Install Suggestions
Write-Host "18. Blocking app suggestions..."
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" `
    -Name "SubscribedContent-338388Enabled" -Value 0 -PropertyType DWORD -Force

# 19. Disable OneDrive Sync
Write-Host "19. Disabling OneDrive Sync..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "OneDrive" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" `
    -Name "DisableFileSyncNGSC" -Value 1 -PropertyType DWORD -Force

# 20. Disable Windows Hello Biometrics
Write-Host "20. Disabling Windows Hello Biometrics..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "Biometrics" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" `
    -Name "Enabled" -Value 0 -PropertyType DWORD -Force

# 21. Disable PowerShell Remote Shell (WinRM)
Write-Host "21. Disabling PowerShell Remote Shell (WinRM)..."
Set-Service -Name WinRM -StartupType Disabled
Stop-Service -Name WinRM -Force

# 22. Final Message
Write-Host "✅ Enhanced Windows hardening complete. Restart recommended." -ForegroundColor Green



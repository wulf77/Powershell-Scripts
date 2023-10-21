# Edits needed: line 7(remove/add exit command to protect yourself), line 15 (username), line 119 (for uninstall package names)
# For user comparison and deletion, run other script separately
# For more difficult problems, try downloading Win. Sysinternal Suite
# In order to run the script, you will need to run the command Set-ExecutionPolicy RemoteSigned
# Meant to be run with the usercompare script found in my Powershell repository

echo "Job 1) ReadMe and forensics questions"
pause

# The following opens a link to the readme
# (Readme link here)
# (Scoring report link here) 
pause

echo "Read through the forensic questions." 
# (Forensic question 1)
# (Forensic question 2) 
pause

echo "Job 2) Miscellaneous, Firewall, auto-downloads, guest account, and password changes."
pause
# Turns the firewall on
# https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior
netsh advfirewall reset
netsh advfirewall set currentprofile state on
netsh advfirewall set AllProfiles state on 
cls

echo "Creating GODMODE folder"
Powershell godmode script: 

# Define the path for the GodMode folder
$godModeFolderPath = "$env:USERPROFILE\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"

# Check if the GodMode folder already exists
if (Test-Path -Path $godModeFolderPath) {
    Write-Host "GodMode folder already exists."
} else {
    # Create the GodMode folder
    New-Item -Path $godModeFolderPath -ItemType Directory

    if (Test-Path -Path $godModeFolderPath) {
        Write-Host "GodMode folder created successfully."
    } else {
        Write-Host "Failed to create GodMode folder."
    }
}




# Starts automatic update downloads
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4
# Start downloading updates
Invoke-Expression -Command "Start-Process -FilePath 'wuapp.exe' -ArgumentList '/updatenow' -Wait"
cls
echo "Start downloading firefox lastest version and any other needed updates not covered by this script manually."
pause 
cls

# Malwarebytes download link- Win 64-bit vers.
echo "Download Malwarebytes and start a scan." 
start-sleep -seconds 3
$url = "https://www.malwarebytes.com/mwb-download/thankyou"
Invoke-Expression "start $url"
pause
cls

# Disables the guest account 
net user Guest /active no 

# Changes all passwords to Cyb3rP@triot23! except for the specified user(s).
$newPassword = ConvertTo-SecureString -String "Cyb3rP@triot23!" -AsPlainText -Force
# Get a list of all user accounts on the computer
$users = Get-LocalUser

# Loop through each user and change their password
foreach ($user in $users) {
    # Skip the user named "eleven"
    if ($user.Name -eq "eleven") {
        Write-Host "Skipping user: $($user.Name)"
        continue
    }

    # Change the password for the user
    try {
        Set-LocalUser -Name $user.Name -Password $newPassword
        Write-Host "Password changed for user: $($user.Name)"
    } catch {
        Write-Host "Error changing password for user: $($user.Name) - $_.Exception.Message"
    }
}

# Define the new password
$newPassword = "Cyb3rP@triot23!"

# Specify the usernames to exclude from password change
$excludedUsers = "eleven"

# Get a list of all user accounts on the computer
$users = Get-WmiObject -Class Win32_UserAccount

# Loop through each user and change their password
foreach ($user in $users) {
    $username = $user.Name

    # Skip the excluded users
    if ($excludedUsers -contains $username) {
        Write-Host "Skipping user: $username"
        continue
    }

    try {
        # Change the password using the net user command
        net user $username $newPassword
        Write-Host "Password changed for user: $username"
    } catch {
        Write-Host "Error changing password for user: $username - $_"
    }
}


echo "enabling ctrl alt del upon login"
pause
# Edits the reg. key to enable ctrl alt del upon login
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
cls
# Define an array of service names
$servicesToDisable = @(
    "SNMPTRAP",
    "RemoteRegistry"
)

# Loop through the services
foreach ($service in $servicesToDisable) {
    # Stop the service if it is running
    if (Get-Service -Name $service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }) {
        Stop-Service -Name $service -Force
    }

    # Configure the service to start as "disabled"
    Set-Service -Name $service -StartupType Disabled
}

# Display a message
Write-Host "Services have been stopped and configured as 'disabled.'"

# Loop through the services
foreach ($service in $servicesToDisable) {
    # Stop the service if it is running
    if (Get-Service -Name $service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }) {
        Stop-Service -Name $service -Force
    }

    # Configure the service to start as "disabled"
    Set-Service -Name $service -StartupType Disabled
}

# Display a message
Write-Host "Services have been stopped and configured as 'disabled.'"

# Pause for user input
pause

# Clear the console
Clear-Host
 
echo "Check services manually according to the readme."
services.msc
pause
cls

echo "Job 3) Audit policies"
# Changes the audit policy in control panel to success, failure.
# Define a list of audit categories to configure (you can add or remove categories as needed)

# NOTE: the auditpol editors do not work as intended yet

# Changes the account policy settings and lockout durations. 
# Define the path to the security configuration template file
$securityConfigPath = "C:\Path\To\AccountPolicy.inf"

# Create the security configuration template
$securityConfig = @"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[System Access]
MinimumPasswordAge = 30
MaximumPasswordAge = 90
MinimumPasswordLength = 10
PasswordComplexity = 1
PasswordHistorySize = 5
[Lockout Policy]
LockoutBadCount = 10
LockoutDuration = 30
ResetLockoutCount = 30
"@
# Save the security configuration to a file
$securityConfig | Out-File -FilePath $securityConfigPath -Encoding Unicode
# Apply the security configuration using secedit.exe
secedit.exe /configure /db "C:\Windows\Security\local.sdb" /cfg $securityConfigPath /areas SECURITYPOLICY
# Remove the temporary security configuration file
Remove-Item -Path $securityConfigPath -Force

# NOTE that the above may not work. here is an alt. option that is far more likely to succeed. 
echo "Running an alternative audit policy modifier." 
pause
# Define the audit and password policy settings
$policySettings = @{
    "AuditSystemEvents" = "3:0:0"
    "AuditLogonEvents" = "2:0:0"
    "AuditObjectAccess" = "3:0:0"
    "AuditPrivilegeUse" = "3:0:0"
    "AuditPolicyChange" = "3:0:0"
    "AuditAccountManage" = "3:0:0"
    "AuditProcessTracking" = "3:0:0"
    "AuditDSAccess" = "3:0:0"
    "AuditAccountLogon" = "2:0:0"
    "MinimumPasswordAge" = "0,1,0"
    "MaximumPasswordAge" = "0,90,0"
    "MinimumPasswordLength" = "0,8,0"
    "PasswordComplexity" = "0,1,0"
    "PasswordHistorySize" = "0,5,0"
    "LockoutBadCount" = "0,10,0"
    "EnableGuestAccount" = "0,0,0"
}

# Export the current local security policy settings to a temporary file
$exportPath = "$env:TEMP\local.cfg"
secedit /export /cfg $exportPath > $null

# Import the existing settings from the temporary file
$existingSettings = Get-Content $exportPath -Raw

# Update the audit and password policy settings in the exported configuration
foreach ($key in $policySettings.Keys) {
    $existingSettings = $existingSettings -replace "$key = .+", "$key = $($policySettings[$key])"
}

# Write the updated settings back to the temporary file
$existingSettings | Set-Content $exportPath

# Apply the changes to the security policy
secedit /configure /db $env:windir\security\local.sdb /cfg $exportPath /areas SECURITYPOLICY
cls

echo "Third time is the charm- last attempt at success/failure auditing." 
pause

<#
.SYNOPSIS
Sets and defines the audit settings in Windows 10 to success and failure for all audit settings in Local Security Policy > Local Policies.

.DESCRIPTION
This function uses the Group Policy cmdlets in PowerShell to configure the audit settings in Windows 10. It sets the audit settings to success and failure for all audit categories in Local Security Policy > Local Policies.

.NOTES
- This function requires administrative privileges to modify the Group Policy settings.
- This function is specifically designed for Windows 10.

.EXAMPLE
Set-AuditSettings
Sets and defines the audit settings in Windows 10 to success and failure for all audit settings in Local Security Policy > Local Policies.
#>
function Set-AuditSettings {
    # Import the Group Policy module
    Import-Module GroupPolicy

    # Get the Local Security Policy object
    $localSecurityPolicy = Get-GPObject -All | Where-Object { $_.DisplayName -eq "Local Security Policy" }

    # Get the Local Policies object
    $localPolicies = Get-GPRegistryValue -Guid $localSecurityPolicy.Id -Key "Machine\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

    # Set the audit settings to success and failure for all audit categories
    foreach ($policy in $localPolicies) {
        $policy.Value = 3  # Set the value to 3 to enable success and failure auditing
    }

    # Save the changes to the Local Security Policy
    Set-GPRegistryValue -Guid $localSecurityPolicy.Id -Key "Machine\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Value $localPolicies

    # Refresh the Group Policy settings
    gpupdate /force
}

# Usage example for the Set-AuditSettings function
Set-AuditSettings

echo "This concludes the editing of the audit policy and password settings. To check manually, hit Enter"
pause
auditpol
pause
cls

echo "Job 4) File system security"
pause
cls

# shows hidden files

echo "Change setting to SHOW hidden files option"
start-sleep -seconds 4 
control folders
pause
cls

echo "Displays unwanted file types:"
# Finds different types of unwanted files in the Users directory
dir C:\
Get-ChildItem -Path C:\Users -Recurse -File -Filter *.txt
Get-ChildItem -Path C:\Users -Recurse -File -Filter *.jpg
Get-ChildItem -Path C:\Users -Recurse -File -Filter *.exe
Get-ChildItem -Path C:\Users -Recurse -File -Filter *.ps1
Get-ChildItem -Path C:\Users -Recurse -File -Filter *.mp3
Get-ChildItem -Path C:\Users -Recurse -File -Filter *.mp4
Get-ChildItem -Path C:\Users -Recurse -File -Filter *.bat
Get-ChildItem -Path C:\Users -Recurse -File -Filter *.jpeg
pause 
cls
pause 
cls

echo "Stop file sharing."
net stop lanmanserver
fsmgmt.msc
pause
# Need to get rid of the shares
echo "Remove any file shares without a $"
net share
pause 
cls

echo "Job 5) Delete unwanted apps"
pause
echo "The following automatically deletes SOME hacking tools and unwanted programs."
start-sleep -seconds 4
Get-Package
Echo "Press 'Enter' to continue."
pause
Start-Process -FilePath "C:\Program Files\Wireshark\uninstall.exe" -Verb RunAs
pause
Start-Process -FilePath "C:\Program Files\Npcap\uninstall.exe" -Verb RunAs
pause 
Start-Process -FilePath "C:\Program Files (x86)\PC Cleaner\PCHSUninstaller.exe" -Verb RunAs
pause
Start-Process -FilePath "C:\Downloads\CCleaner\uninstall.exe" -Verb RunAs
pause
Start-Process -FilePath "C:\Program Files (x86)\Network Stumbler\uninst"
pause
Get-Package
pause
cls
echo "Delete any missed applications manually:"
start-sleep -seconds 3 
appwiz.cpl
pause

echo "Download autoruns program to see programs that start by themselves."
pause
https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns
pause
autoruns
pause
cls

# Turns off remote assistance connections (depending on what the readme instructs.)
# Prompt the user to confirm if they want to disable Remote Assistance
$confirmation = Read-Host "Do you want to disable Remote Assistance (Yes/No)?"

# Check if the user's response is 'Yes' (case-insensitive)
if ($confirmation -eq "Yes" -or $confirmation -eq "Y") {
    # Disable Remote Assistance
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
    Write-Host "Remote Assistance has been disabled."
}
elseif ($confirmation -eq "No" -or $confirmation -eq "N") {
    Write-Host "Remote Assistance remains enabled."
}
else {
    Write-Host "Invalid input. Remote Assistance setting was not changed."
}

echo "This is the end of the script. Proceed to run the second script for weeding out unwanted users."
pause 
cls
# NOW run the separate user compare script, and sort out unwanted users
# (Link to github UserCompare script)
echo "paste this link into your browser for the direct web page to the current verson of my user compare script."
write-host "https://github.com/wulf77/Powershell-Scripts/blob/main/usercompareV2.ps1"
pause 
# Include instructions for both this script and the user compare, and how to run them in a readme file on github




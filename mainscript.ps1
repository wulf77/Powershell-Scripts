#
# In order to run the script, you will need to run the command Set-ExecutionPolicy RemoteSigned
# Edits needed: line 7(remove exit command), line 15 (username), line 119 (for uninstall package names)
# For user comparison and deletion, run other script separately
# For more difficult problems, try downloading Win. Sysinternal Suite



exit

echo "Job 1) ReadMe and forensics questions"
pause

# echo "The following opens a link to the readme:"
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

# Displays the current user's username in prep for password change
echo "Please ensure that you do not change the main account password."
pause 
whoami
pause

# Define the new password
$newPassword = "Cyb3rP@triot23!"

# Prompt the user to enter the names of users to skip password changes
$skipUsers = Read-Host "Enter the name(s) of the user(s) to skip password changes (comma-separated). Press Enter to skip entering a username."

# Split the input into an array of usernames
$excludedUsers = @()
if ($skipUsers -ne "") {
    $excludedUsers = $skipUsers -split ','
}

# Get a list of all user accounts on the computer
$users = Get-WmiObject -Class Win32_UserAccount

# Loop through each user and change their password
foreach ($user in $users) {
    $username = $user.Name

    # Skip the excluded users
    if ($excludedUsers -contains $username) {
        Write-Host "Skipping password change for user: $username"
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
pause 
<#
.SYNOPSIS
Changes the local security policy audit settings and account lockout threshold.

.DESCRIPTION
This function modifies the local group policy object to set the audit settings for success and failure, 
and sets the account lockout threshold to the specified value.

.PARAMETER AccountLockoutThreshold
The value to set for the account lockout threshold.

.EXAMPLE
Set-SecurityPolicy -AccountLockoutThreshold 10
Sets the audit settings for success and failure, and sets the account lockout threshold to 10.
#>
function Set-SecurityPolicy {
    param (
        [int]$AccountLockoutThreshold
    )

    try {
        # Set the audit settings for success and failure
        secedit.exe /export /cfg "$env:TEMP\security.cfg"
        (Get-Content "$env:TEMP\security.cfg") | ForEach-Object {
            $_ -replace "AuditPolicySuccess = 0", "AuditPolicySuccess = 1" `
               -replace "AuditPolicyFailure = 0", "AuditPolicyFailure = 1"
        } | Set-Content "$env:TEMP\security.cfg"
        secedit.exe /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\security.cfg" /areas SECURITYPOLICY

        # Set the account lockout threshold
        $policyPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
        Set-ItemProperty -Path $policyPath -Name "LockoutThreshold" -Value $AccountLockoutThreshold

        Write-Output "Security policy settings updated successfully."
    }
    catch {
        Write-Error "Failed to update security policy settings: $_"
    }
}

# Usage example for the Set-SecurityPolicy function

Set-SecurityPolicy -AccountLockoutThreshold 10

#Manual because the auditpol editors had bugs and only dragged the script down. Will continue to work on a solution."
echo "Check the audit policy settings in local secpol manually."
sleep 2 
echo "Check the Local Sec Pol settings manually. (Hit Win+R and type secpol.)"
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

echo "Download and launch Windows Sysinternal Suites"
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








<# NOTES: 
In order to run the script, you will need to run the command Set-ExecutionPolicy RemoteSigned Remember to remove the exit command below in order to run the script
For user comparison and deletion, run other script separately (link is posted at the end of the script)
It is highly recommended to download Windows Sysinternal Suite

#>


exit

echo "Job 1) ReadMe and forensics questions"
pause

echo "The following opens a link to the readme:"
Start-Process C:\CyberPatriot\README.url
sleep 3
Start-Process C:\CyberPatriot\ScoringReport.html
pause
cls

echo "Read through the forensic questions." 
sleep 3
Start-Process "C:\Users\eleven\Desktop\Forensics Question 1.txt"
pause 
Start-Process "C:\Users\eleven\Desktop\Forensics Question 2.txt"
pause
echo "Don't forget to save the .txt files when done. (Ctrl+S)"
pause 

echo "Job 2) Miscellaneous, Firewall, auto-downloads, guest account, and password changes."
pause
# Turns the firewall on
# https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior
netsh advfirewall reset
netsh advfirewall set currentprofile state on
netsh advfirewall set AllProfiles state on 
cls

<#
echo "Creating GODMODE folder"
Powershell godmode script: 


Error: this part doesn't actually work, and will need to be updated at some future point.

 Define the path for the GodMode folder
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
#>

echo "Enable automatic updates and begin downloading them manually in settings."
pause 
Start-Process "ms-settings:windowsupdate"
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
echo "Disable guest account and limit use of blank passwords to console only."
echo "The path is Win+R -> Local Sec Pol -> Security Settings"
pause
cls

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
# This still needs to be double checked in security options in local sec pol
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 0
cls
# Define an array of service names
$servicesToDisable = @(
    "SNMPTRAP",
    "RemoteRegistry"
    "ftpscv"
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
Set-Service -Name "ftpsvc" -StartupType Disabled
# Display a message
Write-Host "Services have been stopped and configured as 'disabled.'"
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



# Need to get rid of the shares
echo "Review any file shares without a $"
net share
pause 
cls

<#
.SYNOPSIS
Prompts the user to stop the file sharing server.

.DESCRIPTION
Displays a prompt asking the user if they want to stop the file sharing server. 
The default answer is "yes". If the user enters "yes" or presses enter, the file sharing server will be stopped.
#>
function Stop-FileSharingServerPrompt {
    param (
        [string]$DefaultAnswer = "yes"
    )

    # Prompt the user with the default answer
    $answer = Read-Host "Do you want to stop the file sharing server? (Default: $DefaultAnswer)"

    # Check if the user entered "yes" or pressed enter
    if ($answer -eq "" -or $answer.ToLower() -eq "yes") {
        # Stop the file sharing server
        Stop-FileSharingServer
    }
}

<#
.SYNOPSIS
Stops the file sharing server.
#>
function Stop-FileSharingServer {
    # Code to stop the file sharing server goes here
    Write-Output "File sharing server stopped."
}

# Usage example for the Stop-FileSharingServerPrompt.ps1 script

# Prompt the user to stop the file sharing server
Stop-FileSharingServerPrompt

<#
.SYNOPSIS
Prompts the user to stop the Lanman server.

.DESCRIPTION
Displays a prompt asking the user if they want to stop the Lanman server. 
If the user confirms, the Lanman server will be stopped. 
If the user cancels, the script will exit without stopping the server.

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Stop-LanmanServerPrompt
Prompts the user to stop the Lanman server and takes appropriate action based on the user's response.
#>
function Stop-LanmanServerPrompt {
    # Prompt the user to stop the Lanman server
    $response = Read-Host "Do you want to stop the Lanman server? (Y/N)"

    # Convert the user's response to uppercase for case-insensitive comparison
    $response = $response.ToUpper()

    # Check the user's response
    if ($response -eq "Y" -or $response -eq "YES") {
        # Stop the Lanman server
        Stop-Service -Name LanmanServer
        Write-Output "Lanman server stopped."
    }
    elseif ($response -eq "N" -or $response -eq "NO") {
        # User canceled, exit the script
        Write-Output "Lanman server not stopped."
        exit 0
    }
    else {
        # Invalid response, display an error message and exit the script
        Write-Output "Invalid response. Please enter Y or N."
        exit 1
    }
}

# Usage example for the Stop-LanmanServerPrompt function
Stop-LanmanServerPrompt

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




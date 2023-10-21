# Powershell-Scripts

Instructions for running: 
1) Copy/paste the main script into a powershell ISE file on your computer and save it.
2) In order to run it, you will have to open a separate powershell commandline window and run the command "Get-ExecutionPolicy RemoteSigned" (but without the quotes).
3) Make sure you have administrator privileges.
4) Double-click the main script to run it, followed by the usercompareV2.ps1 script after the first one finishes running.

Notes: 
-The main script has several known issues, mainly with blocks of code not working properly. Specifically, the auditpol editing, stopping and starting services, and security configuration for passwords don't always--or ever-- work yet. 
-When attempting to trigger the uninstall.exe files for certain listed programs, it sometimes fails to find the file. I haven't found an easier way to do this yet as filepaths may vary among machines. Therefore, make sure to double check
the apps installed. 

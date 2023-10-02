#
# Script.ps1
#
echo Script requires editing on line 7 for the path to the list file.

# Define the path to the file containing the list of users
$userListFilePath = "C:\Path\To\Your\UserList.txt"

# Read the list of users from the file
$userList = Get-Content -Path $userListFilePath | ForEach-Object { $_.Trim() }

# Get a list of all user accounts on the computer
$systemUsers = Get-LocalUser | Select-Object -ExpandProperty Name

# Initialize arrays to store results
$existingUsers = @()
$missingUsers = @()

# Compare the users from the list with the users on the system
foreach ($user in $userList) {
    if ($systemUsers -contains $user) {
        $existingUsers += $user
    } else {
        $missingUsers += $user
    }
}

# Display the results
Write-Host "Users that exist on the system:"
$existingUsers | ForEach-Object { Write-Host $_ }

Write-Host "Users that do not exist on the system:"
$missingUsers | ForEach-Object { Write-Host $_ }

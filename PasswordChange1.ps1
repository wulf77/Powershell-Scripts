#
# Script.ps1
#
# Define the new password
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

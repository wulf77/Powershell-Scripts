<#
.SYNOPSIS
Compares the users on the machine to the users listed in a file.

.DESCRIPTION
This function reads a file named "userlist.txt" and compares the list of users in the file to the users on the machine.
It outputs the users that are present on the machine but not listed in the file.

.EXAMPLE
CompareUsers
#>
function CompareUsers {
    # Get the list of users from the file
    $userList = Get-Content -Path "userlist.txt"

    # Get the list of users on the machine
    $machineUsers = Get-LocalUser | Select-Object -ExpandProperty Name

    # Compare the two lists and find the users that are present on the machine but not listed in the file
    $missingUsers = Compare-Object -ReferenceObject $machineUsers -DifferenceObject $userList |
                    Where-Object { $_.SideIndicator -eq "=>" } |
                    Select-Object -ExpandProperty InputObject

    # Output the missing users
    if ($missingUsers) {
        Write-Output "The following users are present on the machine but not listed in the file:"
        $missingUsers | ForEach-Object {
            Write-Output $_
        }
    } else {
        Write-Output "All users listed in the file are present on the machine."
    }
}

# Usage example for the CompareUsers function

CompareUsers

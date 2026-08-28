# Import Active Directory module
Import-Module ActiveDirectory

# Import CSV
$Users = Import-Csv .\Users.csv

foreach ($User in $Users) {

    $sam = $User.SamAccountName.Trim()

    # Comprobar si el usuario ya existe
    $existingUser = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue

    if ($existingUser) {
        Write-Host "El usuario '$sam' ya existe." -ForegroundColor Yellow
    }
    else {

        Write-Host "Creando usuario '$sam'..." -ForegroundColor Green

        $userProps = @{
            SamAccountName         = $User.SamAccountName
            Name                   = $User.Name
            GivenName              = $User.GivenName
            Surname                = $User.Surname
            UserPrincipalName      = $User.UserPrincipalName
            Path                   = $User.Path
            AccountPassword        = (ConvertTo-SecureString $User.Password -AsPlainText -Force)
            Enabled                = $true
            ChangePasswordAtLogon  = $false
            PasswordNeverExpires   = $true
        }

        New-ADUser @userProps -ErrorAction Stop
    }
}

Start-Sleep -Seconds 5

# Añadir usuarios a grupos solo si existen
$Memberships = @{
    "Srvc Accounts" = @("roasted.srvc","iis.srvc")
    "Local Admins"  = @("ITAdmin.user")
    "Domain Admins" = @("DAdmin.user")
}

foreach ($groupName in $Memberships.Keys) {

    $group = Get-ADGroup -Identity $groupName -ErrorAction SilentlyContinue

    if (-not $group) {
        Write-Warning "El grupo '$groupName' no existe."
        continue
    }

    foreach ($member in $Memberships[$groupName]) {

        $user = Get-ADUser -Identity $member -ErrorAction SilentlyContinue

        if (-not $user) {
            Write-Warning "El usuario '$member' no existe."
            continue
        }

        # Evitar añadirlo dos veces
        if (Get-ADGroupMember $group | Where-Object SamAccountName -eq $member) {
            Write-Host "'$member' ya pertenece a '$groupName'." -ForegroundColor Yellow
        }
        else {
            Add-ADGroupMember -Identity $group -Members $user
            Write-Host "Añadido '$member' a '$groupName'." -ForegroundColor Green
        }
    }
}
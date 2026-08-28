# Import Active Directory module
Import-Module ActiveDirectory

# Leer el CSV
$ADOU = Import-Csv .\OUs.csv

foreach ($ou in $ADOU) {

    $name = $ou.name.Trim()
    $path = $ou.path.Trim()

    # DN completo de la OU
    $ouDN = "OU=$name,$path"

    # Comprobar si existe
    if (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouDN)" -ErrorAction SilentlyContinue) {

        Write-Host "La OU '$ouDN' ya existe." -ForegroundColor Yellow

    }
    else {

        Write-Host "Creando OU '$ouDN'..." -ForegroundColor Green

        New-ADOrganizationalUnit `
            -Name $name `
            -Path $path `
            -ProtectedFromAccidentalDeletion $false `
            -ErrorAction Stop
    }
}
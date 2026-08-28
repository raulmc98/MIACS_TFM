# Import Active Directory module
Import-Module ActiveDirectory

# Import CSV
$groups = Import-Csv .\Groups.csv

foreach ($group in $groups) {

    $name = $group.name.Trim()
    $path = $group.path.Trim()
    $scope = $group.scope.Trim()
    $category = $group.category.Trim()

    # Comprobar si el grupo ya existe
    $existingGroup = Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue

    if ($existingGroup) {
        Write-Host "El grupo '$name' ya existe." -ForegroundColor Yellow
    }
    else {
        Write-Host "Creando grupo '$name'..." -ForegroundColor Green

        New-ADGroup `
            -Name $name `
            -Path $path `
            -GroupScope $scope `
            -GroupCategory $category `
            -ErrorAction Stop
    }
}
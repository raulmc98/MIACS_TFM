Import-Module GroupPolicy

# Variables
$GpoName = "Deploy Splunk Universal Forwarder"
$OU = "OU=IT Computers,OU=IT,DC=example,DC=com"

# Crear la GPO si no existe
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue

if (-not $gpo) {
    $gpo = New-GPO -Name $GpoName
    Write-Host "GPO creada."
}

# Vincular la GPO a la OU
New-GPLink -Name $GpoName -Target $OU -ErrorAction SilentlyContinue
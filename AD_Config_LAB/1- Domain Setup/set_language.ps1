$lang = New-WinUserLanguageList "es-ES"

$lang[0].InputMethodTips.Clear()
$lang[0].InputMethodTips.Add("040A:0000040A")

Set-WinUserLanguageList $lang -Force

Set-Culture "es-ES"

Set-WinSystemLocale "es-ES"

Write-Host "Idioma configurado."

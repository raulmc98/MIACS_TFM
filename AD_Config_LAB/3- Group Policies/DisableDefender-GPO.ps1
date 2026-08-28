<# this Group Policy can be used to disable the windows defnder or some of its features like 
"Real Time Protection" in domain joined machines, which might be helpful in some security testings #>

#Create the GPO
New-GPO -Name "Disabledefender" -Comment "automate disabling security features"

#Configure the GPOs
Set-GPRegistryValue -Name "Disabledefender" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName DisableRealtimeMonitoring -Type DWord -Value 1
Set-GPRegistryValue -Name "Disabledefender" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName DisableIOAVProtection -Type DWord -Value 1
Set-GPRegistryValue -Name "Disabledefender" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender" -ValueName DisableAntiSpyware -Type DWord -Value 1


#Link the GPO to an Organizational Unit / Domain / Site
New-GPLink -Name "Disabledefender" -Target "ou=IT Computers,ou=IT,dc=miacsdomain,dc=com"

#add the security filtering, uncomment if not needed
Set-GPPermission -Name "Disabledefender" -TargetName "Win-10" -TargetType Computer -PermissionLevel GPOApply
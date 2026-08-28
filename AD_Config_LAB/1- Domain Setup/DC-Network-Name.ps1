# this is to configure the Domain Controller Network settings and Computer name.

netsh int ip set address "ethernet" static 192.168.100.20 255.255.255.0 192.168.100.1 1
netsh int ip set dns "ethernet" static 192.168.100.20 primary
	
Rename-Computer -NewName "DC-01"

Restart-Computer -Force -Verbose
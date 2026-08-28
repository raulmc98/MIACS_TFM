#this script will set the machine's ip address and DNS, then join to the domain and specify its OU path

netsh int ip set address "ethernet" static 192.168.100.10 255.255.255.0 192.168.100.1 1
netsh int ip set dns "ethernet" static 192.168.100.20 primary
#LocalCredential "HostAdmin" is used to specify the local admin account who has permission to run the command. 
#Credential is for Domain Admin who has permission to join the machine to the domain
Add-Computer -DomainName "miacsdomain.com" -NewName "Win-10" -OUPath "OU=IT Computers,OU=IT,DC=miacsdomain,DC=com" -LocalCredential HostAdmin -Credential miacsdomain\administrator -Restart -Force

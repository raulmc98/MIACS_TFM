<# this script is helpful when you have some limited number of users that you want to push to
a limited number of machiness local groups instead of creating Restricted Group Policy.
it was helpful to push the AD users to the "Remote Desktop Users" local group within the joined 
domain machines. It enables us to use the Enhanced Session within Hyper-V
#>

# this is to push users to RDP Groups at target computers for enhanced session at HyperV
Invoke-Command -ComputerName Win-10 -ScriptBlock{Add-LocalGroupMember -Group "Remote Desktop Users" -Member "miacsdomain\user-01", "miacsdomain\admin-01"}

##############################################################################################################################
###  IPA Active Directory user removal Scirpt
###  Version 1.3
###  Created By: Billy Roesener
###  Last Updated: 10/15/2015
##############################################################################################################################

##############################################################################################################################
###  Start Script
##############################################################################################################################

#Checking if Powershell is running as an Administrator.  If not Powershell will reopen as administrator and run the script again
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
#"No Administrative rights, it will display a popup window asking user for Admin rights"

$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments

break
}
#"After user clicked Yes on the popup, your file will be reopened with Admin rights"


##############################################################################################################################
### Setting several variables
##############################################################################################################################
$backupserver = "NAS" #Location of the end location of the finalized ZIP collection
$backuplocation = "\\$backupserver\Backups\Old user profiles\"  #Where on the Backup server do you want to store the files
$PST = "\\Server\pst\" #location of where you want to export the PST to
$Domain = "domain.local" #your AD domain
$pscx = "C:\Program Files (x86)\PowerShell Community Extensions\Pscx3" #location of where PSCX is has been installed to.


Write-Host "******Exchange Mailbox backup and AD User Disable Script ******"
Write-host "Backup Server" $backupserver
Write-Host "Backup Location on Backup Server" $backuplocation
Write-host "location of pst backup" $pst
Write-Host "PSCX is needed for this script to run properly."

Start-Sleep -seconds 2

###############################################################################################################################
### Checking for several non-default powershell modules
###############################################################################################################################
Write-Host "Looking to see if PSCX has been installed"
if (!(Test-Path $pscx)) #have to have ! to check if the path is false.
    {
    Write-Host "PowerShell Community Extensions (PSCX) not found You can download from http://pscx.codeplex.com"
    Start-Sleep -seconds 2
    $a = new-object -comobject wscript.shell 
    $intAnswer = $a.popup("Do you want to download PSCX?", 0,"Download PSCX",4) 
        If ($intAnswer -eq 6) 
            { 
                $a.popup("Taking you to download PSCX. The script will close.")
                start http://pscx.codeplex.com
                Start-Sleep -Seconds 5
                Exit
            } 
        else 
            { 
                $a.popup("You answered no. Exiting Script!")
                Write-Host "exiting the script!"
                Start-Sleep -Seconds 2 
                Exit
            } 
            }
 else
     {
        Write-Host "PSCX was found. Loading Modules"
     }
            
Import-Module pscx
Start-Sleep -seconds 1

#enable script execution for signed scripts, run the following command in an elevated Windows PowerShell window.
Set-ExecutionPolicy RemoteSigned

#Enter your network credentials and store them in a variable by running the following command.
$UserCredential = Get-Credential -Credential "$domain\Administrator"

#Open the connection to Exchange 2013 by running the following command. You must specify the FQDN of an Exchange 2013 Client Access server.
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://server.domain.local/PowerShell -Authentication Kerberos -Credential $UserCredential

#Import the server-side PowerShell session into your client-side session by running the following command.
Import-PSSession $Session

#import Quest AD CMDLET
# Check the QAD snapins are installed
if ( (Get-PSSnapin -Name Quest.ActiveRoles.ADManagement -ErrorAction silentlycontinue) -eq $null ) {
	# The QAD snapin is not active. Check it's installed
	if ( (Get-PSSnapin -Name Quest.ActiveRoles.ADManagement -Registered -ErrorAction SilentlyContinue) -eq $null) {
		Write-Error "You must install Quest ActiveRoles AD Tools to use this script!"
	} else {
		Write-Host "Importing QAD Tools"
		Add-PSSnapin -Name Quest.ActiveRoles.ADManagement -ErrorAction Stop
	}
}

#Import ActiveDirectory Module
Import-Module ActiveDirectory
#Message to show we loaded all Modules 
Write-Host "All Modules loaded and Authenticated to the Exchange Server"
Start-Sleep -seconds 2

#Start the Script
Start-Sleep -seconds 1
#Get user to be disabled and backed up
$username = Read-Host "Enter User Account to be Disabled"
$username = $username.Trim()

#################################################################################################################################################
###  Exchange Export Section
#################################################################################################################################################
#$disabledUsers = @(Get-ADUser -Filter * -SearchBase "ou=Disabled Users,dc=ipa,dc=local" |foreach {$_.SamAccountName})
#    Foreach
#        ($user in $disabledUsers)
#        {
Write-Host "Saving PST to \\SERVER\PST\$username.pst"
Write-Host "Mailbox size" 
Get-MailboxStatistics $username | ft DisplayName, TotalItemSize, ItemCount

Write-Host "May Take a long time check in a new powershell window with 'Get-MailboxExportRequestStatistics -Identity $username\$username' to see the Status"

New-MailboxExportRequest -Name $username -Mailbox $username -FilePath \\ipa-ex-02\PST\$username.pst

#Create a loop which is checking if the task has been finished with 100%
$exstat = Get-MailboxExportRequest | Get-MailboxExportRequestStatistics | where {$_.sourceAlias -eq $username}
Get-MailboxExportRequestStatistics -Identity $username\$username 

do {
    Start-Sleep -Seconds 5;
    $exstat = Get-MailboxExportRequest | Get-MailboxExportRequestStatistics | where {$_.Name -eq $username}
    }

until ($exstat.percentcomplete -eq 100)

Write-Host "All done! Export completed"
Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false

###################################################################################################################################################
###   Start Copying files to the backup location
###################################################################################################################################################

#Create a new folder on IPA-NAS 
Write-host "Creating a new Folder to copy the PST and HomeDrive into on $backupsserver"
#New-Item -ItemType directory -Path $backuplocation$username

#Working with the user's home drive.

#Ask for the home drive location
#need to update and programically get this
Write-Host "Where is the users H: located"
$homedrive = (get-QADUser "$username").homedirectory
Write-Host "$username H: drive found at $homedrive ."
#Move the home to Backupserver 
Write-Host "Moving the home drive to $backupserver"
robocopy /e /NFL /NDL /Move "$homedrive\" $backuplocation"$username\\"

Write-Host "Done moving the Home Drive."
Start-sleep -Seconds 1


#Move the PST to the HomeDrive folder on the backupserver

Write-Host "Moving the $username.pst file to $backupserver"
Write-Host "Checking to see if the file $username.pst is at $pst"
if(test-path -path $pst"$username.pst")
    {
    Write-Host "Yep, $pst"$username.pst" is there."
    }
    else
    {
    Write-Host "Couldn't find $username.pst at $pst."
    }

robocopy /e /Move $pst $backuplocation"$username\\" $username".pst"

Write-host "checking file copied"
Test-Path -Path $backuplocation$username
Write-Host "File Copied it's all good"

##############################################################################################################################
###   zip the home drive and PST
##############################################################################################################################
Write-host "Zipping the folder on the backup server"

$zipfilename = "$username.zip"
$sourcedir = $backuplocation+"$username\"

#This is where PSCX is used for the Write-zip command.
Write-zip $sourcedir $backuplocation$username.zip

Write-host "checking file was created"
Test-Path -Path $backuplocation"$username.zip"
Write-Host "File $username.zip was created it's all good"

###############################################################################################################################
###   Disabling the user and removing membership
###############################################################################################################################

#This is where we hide the user from Exchange
Write-host "Hiding the user from the Exchange Address List"
Set-Mailbox -Identity $username -HiddenFromAddressListsEnabled $true

remove-mailbox -Identity $username -Permanent $true -Confirm:$false

#This is where we disabled the account
#
#Write-Host "Disabling $username."
#Disable-ADAccount -Identity $Username
#
#This is where we specify where the user will be moved in AD.
#

#Get-ADUser $Username | Move-ADObject -TargetPath 'OU=Disabled Users,DC=ipa,Dc=local'


################################################################################################################################
###  All Done! This part of the script closes out the PSSession we started above.
################################################################################################################################
#}
#Use the following command to disconnect remote Shell from an Exchange 2013 server.
Write-Host "All Done.  Getting ready to close the script."
Start-Sleep -Seconds 5

Remove-PSSession $Session
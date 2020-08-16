# Get-IntuneScriptLogs
## Description
A PowerShell script that utilizes the Graph API to easily get script run data from Intune managed computers.

## Features

Running the script with no parameters will give all all script run data for every computer.

`.\Get-IntuneScriptLogs.ps1`

![Usage](/images/AllComputers.PNG)

The script has two parameters, ComputerName and ScriptName

`.\Get-IntuneScriptLogs.ps1 -ComputerName 'MALLOC-navhugr' -ScriptName 'Set-BaseLineStandard`

![Usage](/images/SingleScriptSingleComputer.PNG)


## Additional Info
Two DLL files are required to get an Access token from Azure, I've included those files in the repository so the script will automatically load them
and use them. If the files are not there it will look for the Azure AD module for the DLLs and if not, attempt to install the AzureAD module to get the DLLs that way. Shoutout to all the people working on the 
PowerShell Intune Samples [repo](https://github.com/microsoftgraph/powershell-intune-samples). I've used a slightly modified version of the Get-AuthToken function.

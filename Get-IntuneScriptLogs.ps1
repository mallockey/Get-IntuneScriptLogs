param(
    [String]$ComputerName,
    [String]$ScriptName
)

function Get-AzureAdModuleInstallStatus {

    $AzureADModulePath = (Get-Module -Name AzureAD -ListAvailable).Path
    if($AzureADModulePath){
        return Split-Path -Path $AzureADModulePath -Parent
    }else{
        return $False
    }

}
function Get-AzureDLLPath {

    $ScriptPathDLLs = '.\Microsoft.IdentityModel.Clients.ActiveDirectory.dll',
                      '.\Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll'

    $PathValidCount = 0
    $ScriptPathDLLs | Foreach-Object{
        if(Test-Path $_){
            $PathValidCount++
        }
    }
    
    if($PathValidCount -eq 2){
        return '.\'
    }

    $AzureADPath = Get-AzureAdModuleInstallStatus
    if($AzureADPath){
        return $AzureADPath
    }else{
        try{
            Install-Module -Name AzureAD -Scope CurrentUser -Force
        }catch{
            Write-Output "There was an error installing the Azure AD module, please install manually and rerun the script."
            Write-Output $_.Exception.Message
            exit
        }

        $AzureADPath = Get-AzureAdModuleInstallStatus
        if($AzureADPath){
            return $AzureADPath
        }else{
            Write-Output "DLL was not detected after installing Azure AD module"
            exit
        }
    }
    
}
function Get-AuthToken {
   
    [cmdletbinding()] 
    param(
        [Parameter(Mandatory=$True)]
        $User
    )

    $UserUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    $Tenant = $UserUpn.Host

    $AzureDLLPath = Get-AzureDLLPath

    [System.Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath (Join-Path $AzureDLLPath '.\Microsoft.IdentityModel.Clients.ActiveDirectory.dll'))) | Out-Null
    [System.Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath (Join-Path $AzureDLLPath '.\Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll') )) | Out-Null

    $ClientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    $RedirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $ResourceAppIdURI = "https://graph.microsoft.com"
    $Authority = "https://login.microsoftonline.com/$Tenant"

    try{
        $AuthContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $Authority
        $PlatformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
        $UserId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
        $AuthResult = $AuthContext.AcquireTokenAsync($ResourceAppIdURI,$ClientId,$RedirectUri,$PlatformParameters,$UserId).Result

        if($AuthResult.AccessToken){
            $AuthHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $AuthResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
            }

        return $AuthHeader

        }
        else{
            Write-Output "Authorization Access Token is null, please re-run authentication..." 
            exit
        }

    }
    catch{
        Write-Output $_.Exception.Message
        Write-Output $_.Exception.ItemName 
        exit
    }
} 

function Format-Data{

    param(
        $InputData
    )

    $ScriptLogProps = [Ordered]@{
        ScriptName = $Null
        ComputerName = $Null
        RunState = $Null
        ResultMessage = $Null
        ErrorCode = $Null
        ErrorDescription = $Null
        lastStateUpdateDateTime = $Null
    }
 
    $Counter = 0
    foreach($Data in $InputData){

        $ScriptLogObj = New-Object -TypeName PSObject -Property $ScriptLogProps
        $ScriptLogObj.ComputerName = Get-AzurePCNameById -ScriptDeviceStateID $Data.ID
        $ScriptLogObj.ScriptName = Get-AzureScriptNameByID -ScriptDeviceStateID $Data.ID
        $ScriptLogObj.RunState = $Data.runState
        $ScriptLogObj.ResultMessage = $Data.ResultMessage
        $ScriptLogObj.ErrorCode = $Data.errorCode
        $ScriptLogObj.ErrorDescription = $Data.ErrorDescription
        $ScriptLogObj.lastStateUpdateDateTime = $Data.lastStateUpdateDateTime
        
        [Int]$CurrentPercent = (($Counter / $InputData.Count) * 100)
        Write-Progress -Activity "Compiling Script Run Data for $($ScriptLogObj.ScriptName) script" -Status "Current Computer: $($ScriptLogObj.ComputerName)" -CurrentOperation "$CurrentPercent% completed" -PercentComplete $CurrentPercent

        $ScriptLogObj
        $Counter++
    }

}

function Get-AzureScriptNameByID{

    param(
        [String]$ScriptDeviceStateID
    )

    $ScriptName = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/" `
                                  -Headers $Global:AuthToken | `
                                   Select-Object -ExpandProperty Value | `
                                   Where-Object {$ScriptDeviceStateID -like "$($_.ID)*"}  | `
                                   Select-Object -ExpandProperty displayName

    return $ScriptName
}

function Get-AzurePCNameByID {

    param(
        [String]$ScriptDeviceStateID
    )

    $DeviceName = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devicemanagement/managedDevices" `
                                    -Headers $Global:AuthToken -Method Get  | `
                                     Select-Object -ExpandProperty Value  | `
                                     Where-Object {$ScriptDeviceStateID -like "*$($_.ID)"} | `
                                     Select-Object -ExpandProperty DeviceName

    return $DeviceName

}
function Get-AzureIDByComputerName{

    param(
        [String]$ComputerName
    )

    $DeviceID = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/devicemanagement/managedDevices" `
                                  -Headers $Global:AuthToken -Method Get  | `
                                   Select-Object -ExpandProperty Value  | `
                                   Where-Object {$_.DeviceName -eq $ComputerName} |
                                   Select-Object -ExpandProperty ID

    return $DeviceID
    
}

function Get-AzureScriptIDByName{

    param(
        [String]$ScriptName
    )

    $ScriptID = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/" `
                                   -Headers $Global:AuthToken | `
								   Select-Object -ExpandProperty Value | `
                                   Where-Object {$_.DisplayName -eq $ScriptName} | `
                                   Select-Object -ExpandProperty ID
								   
    return $ScriptID
}

##########################################Start here#################################
$ErrorActionPreference = "Stop"

if($Global:AuthToken){

    $DateTime = (Get-Date).ToUniversalTime()
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
    
    if($TokenExpires -le 0){
        Write-Output  "Authentication Token expired $TokenExpires minutes agos"
        $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
        $Global:AuthToken = Get-AuthToken -User $User
    }

}else{
    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    $Global:AuthToken = Get-AuthToken -User $User
}

if($ScriptName){#If user wants logs on a specific script
  
    $ScriptIDs = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/" `
                                   -Headers $Global:AuthToken | `
                                    Select-Object -ExpandProperty Value | `
                                    Where-Object {$_.DisplayName -eq $ScriptName} | `
                                    Select-Object -ExpandProperty ID
}else{#Otherwise get all the scripts
    $ScriptIDs = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/" `
                                   -Headers $Global:AuthToken | `
                                    Select-Object -ExpandProperty Value | `
                                    Select-Object -ExpandProperty ID
    
}

$AllScriptData = [System.Collections.ArrayList]@()      
foreach($Script in $ScriptIDs){
    
    $ScriptRun = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$Script/deviceRunStates" `
                                   -Headers $Global:AuthToken | `
                                    Select-Object -ExpandProperty Value

    foreach($ScriptRunInstance in $ScriptRun){
        $AllScriptData.Add($ScriptRunInstance) | Out-Null
    }
}

if($ComputerName){
    $TempData = Format-Data -InputData $AllScriptData 
    $TempData | Where-Object {$_.ComputerName -eq $ComputerName} | Sort-Object ScriptName
}else{
    Format-Data -InputData $AllScriptData | Sort-Object ScriptName
}

Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web

function Connect-Zerotier {
    param(
        [Parameter(Mandatory=$true)][string]$apitoken
    )
    [securestring]$secureToken = $apitoken | ConvertTo-SecureString -AsPlainText -Force
    $secureToken | ConvertFrom-SecureString | Set-Content -Path $zeroTierConfig.apiTokenFile
    Write-host "Connected to NSOne`n"
}

function Disconnect-Zerotier {
    Remove-Item -Path $zeroTier.apiTokenFile | Out-Null
    $zeroTierConfig.apiCredientials = $null
}

function Get-ZeroTierMember {
    param(
        [Parameter(Mandatory=$true,Position=0)][string]$networkId,
        [Parameter(Mandatory=$false,Position=1)][string]$memberId
    )
    <#
    GET /api/v1/network/{networkID}/member/{memberID}
    #>
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($memberId) {
        $uri = "$($zeroTierConfig.baseApiUrl)/api/v1/network/$networkID/member/$memberId"
    } else {
        $uri = "$($zeroTierConfig.baseApiUrl)/api/v1/network/$networkID/member"
    }
    try {
        $webresponse = invoke-webrequest -uri $uri -method Get -headers @{"Authorization" = "Bearer $($zeroTierConfig.apiCredientials)"} -ContentType "application/json"
        ConvertFrom-JSON $webresponse.Content
    } catch {
        Set-ZeroTierRESTErrorResponse
    }
}

function Set-ZerotierMember {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline)][PSObject[]]$records,
        [Parameter(Mandatory=$false,Position=0)]$name,
        [Parameter(Mandatory=$false,Position=1)]$description,
        [Parameter(Mandatory=$false,Position=2)]$authorized,
        [Parameter(Mandatory=$false,Position=3)]$hidden
    )
    Begin {
    }
    Process {
        foreach ($record in $records) { 
            $psBody = @{}
            if ($hidden -ne $Null) {
                $psBody.hidden += hidden
            } else {
                $psBody.hidden += $record.hidden
            }
            if ($name -ne $Null) {
                $psBody.name += $name
            } else {
                $psBody.name += $record.name
            }
            if ($description -ne $Null) {
                $psBody.description += $description
            } else {
                $psBody.description += $record.description
            }
            $config = $record.config
            $psBody.config += @{ActiveBridge = $config.activeBridge}
            if ($authorized -ne $Null) {
                $psBody.config += @{authorized = $authorized}
            } else {
                $psBody.config += @{authorized = $config.authorized}
            }
            $psBody.config += @{capabilities = $config.capabilities}
            $psBody.config += @{noAutoAssignIps = $config.noAutoAssignIps}
            $psBody.config += @{tags = $config.tags}
            $jsonBody = $psBody | ConvertTo-Json -depth 99
            $jsonBody
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $uri = "$($zeroTierConfig.baseApiUrl)/api/v1/network/$($record.networkID)/member/$($record.nodeId)"
            try {
                $webresponse = invoke-webrequest -uri $uri -body $jsonBody -method Post -headers @{"Authorization" = "Bearer $($zeroTierConfig.apiCredientials)"} -ContentType "application/json"
                ConvertFrom-JSON $webresponse.Content
            } catch {
                Set-ZeroTierRESTErrorResponse
            }
        }
    }
    end {
    }
}

function Get-ZerotierLogonEvents {
    param(
        [Parameter(Mandatory=$true,Position=0)][string]$networkId
    )
    $cacheFile = "$($zerotierConfig.apiCacheDir)\$networkId.cache"
    if (Test-Path $cacheFile) {
        $lastMemberList = Import-CliXml $cacheFile
    }
    $newMemberList = Get-ZeroTierMember $networkId
    foreach ($member in $($newMemberList | where-object {$_.online -eq $true})) {
        $wasOnline = ($lastMemberList | where-object {$_.id -eq $member.id}).online
        if ($wasOnline -ne $true) {
            $member
        }
    }
    $newMemberList | Export-Clixml $cacheFile -Force
}

function Set-ZeroTierRESTErrorResponse {
    if ($_.Exception.Response) {
        $zeroTierRESTErrorResponse.apiCredientials = $nsoneConfig.apiCredientials
        $zeroTierRESTErrorResponse.statusCode = $_.Exception.Response.StatusCode
        $zeroTierRESTErrorResponse.statusDescription = $_.Exception.Response.StatusDescription
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $zeroTierRESTErrorResponse.responseBody = $reader.ReadToEnd();
        $zeroTierRESTErrorResponse.responseError = $zeroTierRESTErrorResponse.responsebody
        $zeroTierRESTErrorResponse
    } else {
        write-error $_
    }
    break
}

function Format-ZerotierTimeStamp {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline)][PSObject[]]$sourceObjects,
        [Parameter(Mandatory=$true)][string[]]$properties,
        [Parameter(Mandatory=$false)][string]$format,
        [Parameter(Mandatory=$false)][int]$offset
    )
    begin {
    }
    process {
        foreach ($sourceObject in $sourceObjects) {
            foreach ($property in $properties) {
                $timestamp = $sourceObject.$property / 1000
                if ($offset) {
                    $timestamp = +$timestamp + (+$offset * 3600)
                }
                $dateTime = (Get-Date '1970-01-01 00:00:00').AddSeconds($timeStamp)
                if ($format) {
                    $dateTime = $dateTime.ToString($format)
                }
                $sourceObject.$property = $dateTime
            }
            $sourceObject
        }
    }
    end {
    }
}

# get values for API access
$zerotierConfig = [ordered]@{
    baseApiURL = "https://my.zerotier.com"
    apiTokenFile = "$HOME\.zerotier-api-token"
    apiCacheDir = "$HOME"
    apiCredientials = $null
}
New-Variable -Name nsoneconfig -Value $nsoneConfig -Scope script -Force
$zerotierRESTErrorResponse = [ordered]@{
    apiToken = $null
    statusCode = $null
    statusDescription = $null
    responseBody = $null
    responseError = $null
}
New-Variable -Name zerotierRESTErrorResponse -Value $zerotierRESTErrorResponse -Scope script -Force
if ( Test-Path $zerotierConfig.apiTokenFile ) {
    $apiToken = Get-Content $zerotierConfig.apiTokenFile | ConvertTo-SecureString -Force
    $zerotierConfig.apiCredientials = (New-Object System.Management.Automation.PsCredential -ArgumentList "ZEROTIER TOKEN", $apiToken).GetNetworkCredential().Password
    Write-host "Connected to NSOne`n"
}
else {
    Write-Warning "Autoconnect failed.  API token file not found.  Use Connect-Zerotier to connect manually."
}
Write-host "Cmdlets added:`n$(Get-Command | where {$_.ModuleName -eq 'Zerotier.PSHelper'})`n"
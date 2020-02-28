## Use VirusTotal to scan a URL
## Chris Shearer
## 2.26.2020
## VirusTotal Public API: https://developers.virustotal.com/reference#url-scan

## Get your own VT API key here: https://www.virustotal.com/gui/join-us
    $VTApiKey = "xxxxxxxxxxxxxxxxxxx"

## Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

## Zero out counter
    $n = 0

Function submit-VTURL($VTURL)
{
    #$vtresult = $null
    $VTbody = @{url = $VTURL; apikey = $VTApiKey}
    $VTscan = Invoke-RestMethod -Method POST -Uri 'https://www.virustotal.com/vtapi/v2/url/scan' -Body $VTbody
    return $VTscan
}

Function search-VTURL($currentResource)
{
    #$vtresult = $null
    $VTbody = @{resource = $currentResource; apikey = $VTApiKey}
    $VTReport = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/url/report' -Body $VTbody
    return $VTReport
}

Function Start-SleepyTime
{   
    if ($n -ge ($samples.count * 2)) {$SleepyTime = 0}
    Write-host -f Yellow "Sleeping to avoid API limits. $SleepyTime seconds"
    Start-Sleep -seconds $SleepyTime
}

## Samples
    $samples = @("microsoft.com","apple.com")

## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
    if ($samples.count -ge 2) {$SleepyTime = 15}
    else {$SleepyTime = 0 }

## Loop through URLs
    foreach ($URL in $samples)
        {
            ## Run the function to submit the url for scanning
                Write-Host -f Green "Scanning URL: " -nonewline; write-host $URL
                $VTresult = submit-VTURL($URL)
            
            if ($vtresult.response_code -eq 1)
                {
                    ## Submission was successful, now we need to hang around and get the result using $vtresult.scan_id
                        Write-Host "===URL SCAN SUBMITTED==="
                        Write-Host -f Cyan "Result    : " -NoNewline; Write-Host $vtresult.verbose_msg
                        Write-Host -f Cyan "Permalink : " -NoNewline; Write-Host $vtresult.permalink
                        Write-Host -f Cyan "Scan ID   : " -NoNewline; Write-Host $vtresult.scan_id
                        Write-Host -f Cyan "Resource  : " -NoNewline; Write-Host $vtresult.resource
                        Write-Host "========================`n"

                    ## Run function to sleep for the right amount of time because we just did an API call
                        $n = $n + 1
                        Start-SleepyTime
                        
                    ## Set the current resource we are looking at to a variable to cleanly pass into the function
                        $currentResource = $vtresult.resource
                        $VTReport = search-VTURL($currentResource)

                    ## Color positive results
                        if ($VTreport.positives -ge 1) 
                            {
                                $fore = "Magenta"
                                $vtRatio = (($VTReport.positives) / ($VTReport.total)) * 100
                                $vtRatio = [math]::Round($vtRatio,2)
                            }

                        else 
                            {
                                $fore = (get-host).ui.rawui.ForegroundColor
                                $vtRatio = 0
                            }

                    ## Display results 
                        Write-Host "=======URL REPORT======="
                        Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTReport.resource
                        Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTReport.scan_date
                        Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTReport.positives -f $fore
                        Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTReport.total
                        Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTReport.permalink
                        Write-Host -f Cyan "Ratio       : " -NoNewline; Write-Host $vtRatio -f $fore
                        Write-Host "========================`n"
                }
            else 
                {
                    Write-Host "Something went wrong:"
                    Write-Host $VTresult.verbose_msg
                }
            
            ## Run function to sleep for the right amount of time because we just did an API call
                $n = $n + 1    
                Start-SleepyTime
        }
Function submit-VTURL($VTURL)
{
    #$vtresult = $null
    $VTbody = @{url = $VTURL; apikey = $VTApiKey}
    $VTscan = Invoke-RestMethod -Method POST -Uri 'https://www.virustotal.com/vtapi/v2/url/scan' -Body $VTbody
    return $VTscan
}

Function search-VTURL($currentResource)
{
    #$vtresult = $null
    $VTbody = @{resource = $currentResource; apikey = $VTApiKey}
    $VTReport = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/url/report' -Body $VTbody
    return $VTReport
}

Function Start-SleepyTime
{
    Write-host -f Yellow "Sleeping to avoid API limits. $SleepyTime seconds"
    Start-Sleep -seconds $SleepyTime
}

## Samples
    $samples = @("microsoft.com","apple.com")

## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
    if ($samples.count -ge 2) {$SleepyTime = 15}
    else {$SleepyTime = 1 }

## Loop through URLs
    foreach ($URL in $samples)
        {
            ## Run the function to submit the url for scanning
                Write-Host -f Green "Scanning URL: " -nonewline; write-host $URL
                $VTresult = submit-VTURL($URL)
            
            ## Run  function to sleep for the right amount of time
                Start-SleepyTime
            
            if ($vtresult.response_code -eq 1)
                {
                    ## Submission was successful, now we need to hang around and get the result using $vtresult.scan_id
                        Write-Host "===URL SUBMITTED==="
                        Write-Host -f Cyan "Result    : " -NoNewline; Write-Host $vtresult.verbose_msg
                        Write-Host -f Cyan "Permalink : " -NoNewline; Write-Host $vtresult.permalink
                        Write-Host -f Cyan "Scan ID   : " -NoNewline; Write-Host $vtresult.scan_id
                        Write-Host -f Cyan "Resource  : " -NoNewline; Write-Host $vtresult.resource
                        Write-Host "===================`n"

                    ## Run our function to sleep for the right amount of time
                        Start-SleepyTime
                        
                    ## Set the current resource we are looking at to a variable to cleanly pass into the function
                        $currentResource = $vtresult.resource
                        $VTReport = search-VTURL($currentResource)

                    ## Color positive results
                        if ($VTreport.positives -ge 1) 
                            {
                                $fore = "Magenta"
                                $vtRatio = (($VTReport.positives) / ($VTReport.total)) * 100
                                $vtRatio = [math]::Round($vtRatio,2)
                            }

                        else 
                            {
                                $fore = (get-host).ui.rawui.ForegroundColor
                                $vtRatio = 0
                            }

                    ## Display results 
                        Write-Host "====URL REPORT====="
                        Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTReport.resource
                        Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTReport.scan_date
                        Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTReport.positives -f $fore
                        Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTReport.total
                        Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTReport.permalink
                        Write-Host -f Cyan "Ratio       : " -NoNewline; Write-Host $vtRatio -f $fore
                        Write-Host "===================`n"
                }
            else 
                {
                    Write-Host "Something went wrong:"
                    Write-Host $VTresult.verbose_msg
                }
        }

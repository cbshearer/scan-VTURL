## Use VirusTotal to scan a URL
## Chris Shearer
## 2.26.2020
## VirusTotal Public API: https://developers.virustotal.com/reference#url-scan

## Get your own VT API key here: https://www.virustotal.com/gui/join-us
    $VTApiKey = "xxxxxxxxxxxxxxxxxxx"

## Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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

Function start-apisleep
{
    Write-host "`nSleeping to avoid API limits!"
    Start-Sleep -seconds $sleepTime
}

## Samples
    $samples = @("http://internetyellowpages.buzz/Chase/chase/verification/5CACBBN043094ADCD1CM/card.php","http://bonuspacex.com/btc/")

## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
    if ($samples.count -ge 2) {$sleepTime = 15}
    else {$sleepTime = 1 }

## Loop through URLs
    foreach ($URL in $samples)
        {
            ## Run the function to submit the url for scanning
                $VTresult = submit-VTURL($URL)
            
            ## Run our function to sleep for the right amount of time
                start-apisleep
            
            if ($vtresult.response_code -eq 1)
            {
                ## submission was successful, now we need to hang around and get the result using $vtresult.scan_id
                    Write-Host "===URL SUBMITTED==="
                    Write-Host -f Cyan "Result    : " -NoNewline; Write-Host $vtresult.verbose_msg
                    Write-Host -f Cyan "Permalink : " -NoNewline; Write-Host $vtresult.permalink
                    Write-Host -f Cyan "Scan ID   : " -NoNewline; Write-Host $vtresult.scan_id
                    Write-Host -f Cyan "Resource  : " -NoNewline; Write-Host $vtresult.resource
                
                ## Run our function to sleep for the right amount of time
                    start-apisleep
                    
                ## Set the current resource we are looking at to a variable to cleanly pass into the function
                    $currentResource = $vtresult.resource
                    $VTReport = search-VTURL($currentResource)

                ## Color positive results
                    if ($VTreport.positives -ge 1) {
                        $fore = "Magenta"
                        $vtRatio = (($VTReport.positives) / ($VTReport.total)) * 100
                        $vtRatio = [math]::Round($vtRatio,2)
                        }

                    else {
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
            }
        }

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

## Samples
    $samples = @("competent-meninsky-ff3ae0.netlify.com")

## Loop through URLs
    foreach ($URL in $samples)
        {
            ## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
                if ($samples.count -ge 4) {$sleepTime = 15}
                else {$sleepTime = 1 }
            
            #$VTresult = $null
            $VTresult = submit-VTURL($URL)

            if ($vtresult.response_code -eq 1)
            {
                ## submission was successful, now we need to hang around and get the result using $vtresult.scan_id
                Write-Host -f Cyan "Result    : " -NoNewline; Write-Host $vtresult.verbose_msg
                Write-Host -f Cyan "Permalink : " -NoNewline; Write-Host $vtresult.permalink
                Write-Host -f Cyan "Scan date : " -NoNewline; Write-Host $vtresult.scan_date
                Write-Host -f Cyan "Resource  : " -NoNewline; Write-Host $vtresult.resource

                <#
                    now i ave to write a query to search against the $vtresult.scan_id portion
                #>
            }



            <#
            ## Color positive results
                if ($VTresult.positives -ge 1) {
                    
                    $fore = "Magenta"
                    $vtRatio = (($VTresult.positives) / ($VTresult.total)) * 100
                    $vtRatio = [math]::Round($vtRatio,2)
                
                }
                else 
                {
                    $fore = (get-host).ui.rawui.ForegroundColor
                    $vtRatio = 0
                }

            ## Display results
                Write-Host "==================="
                Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTresult.resource
                Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTresult.scan_date
                Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTresult.positives -f $fore
                Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTresult.total
                Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTresult.permalink
                Write-Host -f Cyan "Ratio       : " -NoNewline; Write-Host $vtRatio -f $fore
                #>
                Start-Sleep -seconds $sleepTime
        }

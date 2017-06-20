<#
    .SYNOPSIS
        Function to check for Wanna Cry vulnerability on Server 2008R2, 2012, & 2012 R2
    .DESCRIPTION
        Function to check for Wanna Cry vulnerability on Server 2008R2, 2012, & 2012 R2
            Examines the file version of C:\Windows\System32\win32k.sys for a new enough version
            Examines whether the patches to remediate Wanna Cry have been installed
            Outputs color output to the screen for easy viewing
            Outputs csv files to for All, Healthy, Unknown, and Vulnerable Servers
    .PARAMETER InputObject
        Computer FQDNs (Fully Qualified Domain Names) to execute code vulnerability check against.
    .PARAMETER OutputDirectory
        Directory for file output.  Defaults to $env:USERPROFILE\Documents which will usually be C:\Users\<Username>\Documents
    .PARAMETER Passthru
        By default, you will see output on the screen and in the files.  If you want an object returned
        that you can manipulate in PowerShell, add the -passthru to return an object containing all servers.
    .PARAMETER VulnerabilityManifest
        A .psd1 file containing an array of hashtables specifying the vulnerability name, KBs which will remediate
        the vulnerability, a file to check for a specific version that ensures the patch has been correctly installed,
        and the version numbers of the file for each version of Windows.  An annotated example is given below:

            @(
                @{
                    VulnerabilityName = 'WannaCry' #this will be used when naming output files
                    
                    ApplicableHotfixes = @('KB4012214','KB4012217','KB4012213','KB4012216','KB4012212','KB4012215','KB4012606','4013198','4013429') # WannaCry:s https://technet.microsoft.com/library/security/MS17-010
                    
                    TargetFile = 'C:\Windows\System32\win32k.sys' #we will check this file's version
                    
                    FileVersions = @{
                        Win6_1      = '6.1.7601.23677'   #https://support.microsoft.com/en-us/help/4012212/march-2007-security-only-quality-update-for-windows-7-sp1-and-windows-server-2008-r2-sp1 
                        Win6_2      = '6.2.9200.22099'   #https://support.microsoft.com/en-us/help/4012217/march-2017-security-monthly-quality-rollup-for-windows-server-2012
                        Win6_3      = '6.3.9600.18603'   #https://support.microsoft.com/en-us/help/4012213/march-2017-security-only-quality-update-for-windows-8-1-and-windows-server-2012-r2
                        Win10_10240 = '10.0.10240.16384' #https://support.microsoft.com/en-sg/help/4019474 and scroll down to Fle Information bullet to download the CSV list of file versions.
                        Win10_10586 = '10.0.10586.20'    #https://support.microsoft.com/en-sg/help/4019473 and scroll down to Fle Information bullet to download the CSV list of file versions.
                        Win10_14393 = '10.0.14393.594'   #https://support.microsoft.com/en-sg/help/4013429 and scroll down to Fle Information bullet to download the CSV list of file versions.
                        Win10_15063 = '10.0.15063.0'     #https://support.microsoft.com/en-sg/help/4020102 and scroll down to Fle Information bullet to download the CSV list of file versions.
                    }
                }
                #create additional hash tables here to process multiple vulns or multiple files
            )

    .EXAMPLE
        First you'll need to define the vulnerability that you're looking for:
        Start with virus definition manifest file like this with a `.psd1` extention, named, for example,  `vuln.psd1`.

        The following definition will find vulnerability for the ransomware [WannaCry][WannaCryLink].
        
        @(
            @{
                VulnerabilityName = 'WannaCry' #this will be used when naming output files
                
                ApplicableHotfixes = @('KB4012214','KB4012217','KB4012213','KB4012216','KB4012212','KB4012215','KB4012606','4013198','4013429') # WannaCry:s https://technet.microsoft.com/library/security/MS17-010
                
                TargetFile = 'C:\Windows\System32\win32k.sys' #we will check this file's version
                
                FileVersions = @{
                    Win6_1      = '6.1.7601.23677'   #https://support.microsoft.com/en-us/help/4012212/march-2007-security-only-quality-update-for-windows-7-sp1-and-windows-server-2008-r2-sp1 
                    Win6_2      = '6.2.9200.22099'   #https://support.microsoft.com/en-us/help/4012217/march-2017-security-monthly-quality-rollup-for-windows-server-2012
                    Win6_3      = '6.3.9600.18603'   #https://support.microsoft.com/en-us/help/4012213/march-2017-security-only-quality-update-for-windows-8-1-and-windows-server-2012-r2
                    Win10_10240 = '10.0.10240.16384' #https://support.microsoft.com/en-sg/help/4019474 and scroll down to Fle Information bullet to download the CSV list of file versions.
                    Win10_10586 = '10.0.10586.20'    #https://support.microsoft.com/en-sg/help/4019473 and scroll down to Fle Information bullet to download the CSV list of file versions.
                    Win10_14393 = '10.0.14393.594'   #https://support.microsoft.com/en-sg/help/4013429 and scroll down to Fle Information bullet to download the CSV list of file versions.
                    Win10_15063 = '10.0.15063.0'     #https://support.microsoft.com/en-sg/help/4020102 and scroll down to Fle Information bullet to download the CSV list of file versions.
                }
            }
        )
        
        *For more information on sourcing the information for the manifest file, view the VulnerabilityManifest.psd1 file included with this module.*

    .EXAMPLE
        Invoke-PSVulnCheck -ComputerName @('server1','server2') -Vuln vuln.psd1
            Checks server1 and server2 for the vulnerability specified in the vuln.psd1 file.  Writes 4 output files to C:\Temp\PSVulnCheck.  Displays color coded output screen.

    .EXAMPLE
        Get-Content C:\Temp\servers.txt |  Invoke-PSVulnCheck
            Pulls a list of servers (1 [FQDN](https://www.google.com/search?q=FQDN&ie=utf-8&oe=utf-8) per line) using the pipeline and checks for vulnerability.  Note, due to the use of invoke-parallel to speed processing, you cannot [specify the value from pipeline by property name](https://blogs.technet.microsoft.com/heyscriptingguy/2013/03/25/learn-about-using-powershell-value-binding-by-property-name/).  You must pass in an array of strings `[string[]]`.

    .EXAMPLE
         $results = Get-Content C:\Temp\servers.txt | Invoke-PSVulnCheck -OutputDirectory 'C:\Temp\AssetCheck' -passthru
            Same as above except results will be placed in `C:\Temp\AssetCheck`.
            By using the -passthrue parameter, an array of  `[PSCustomObjects[]]` will be returned and stored in the variable $results for you to utilize.

    .EXAMPLE
        The following example uses the `servers.csv` file containing this code:

            server,role
            server1.contoso.com,app
            server2.contoso.com,app
            server3.contoso.com,app
            server4.contoso.com,wfe
            server5.contoso.com,wfe
            server6.contoso.com,wfe
            server7.contoso.com,sql
            server8.contoso.com,sql
            server9.contoso.com,wac
            server10.contoso.com,wac

        (Import-Csv C:\Temp\servers.csv).server | Invoke-PSVulnCheck
            This functions the same as the previous example, but provides more insight in how to pass a named property into the command.

    .FUNCTIONALITY
        PowerShell Language
    .NOTES
        Credit to Warren Frame for Invoke-Parallel: https://github.com/RamblingCookieMonster/Invoke-Parallel
        Credit to SharePoint Online 365 PAV team for assistance.
    .LINK
        https://github.com/chmadole/PSVulnCheck
#>

Function Invoke-PSVulnCheck {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Alias('CN', '__Server', 'IPAddress', 'Server', 'ComputerName')]
        [string[]] $InputObject,
        
        [string]   $OutputDirectory = "$env:USERPROFILE\Documents",

        [Alias('VulnManifest', 'Vuln')]
        [object]   $VulnerabilityManifest = "$PSScriptRoot\..\VulnerabilityManifest.psd1",
        
        [switch]   $Passthru
    )

    Begin {
        #adapted from https://stackoverflow.com/questions/23066783/how-to-strip-illegal-characters-before-trying-to-save-filenames
        Function Get-FileNameRemoveInvalidChar {
            param(
                [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
                [String[]]$FileName
            )
            Begin {
                $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
                $regex = "[{0}]" -f [RegEx]::Escape($invalidChars)
            }
            Process {
                Foreach ($file in $filename) {
                    Write-Output ($File -replace $regex)
                }
            }
            End {}
        }
    }
    #Process{} - omitted to facilitate Invoke-Parallel Processing
    End {
        #handle pipeline and non-pipeling input -- put both into the same $ComputerName value
        if ($input) {$ComputerName = [array]$input}
        else {$ComputerName = $InputObject}

        $vulns = [array](Import-LocalizedData -BaseDirectory (split-path -parent $vulnerabilityManifest) -FileName (split-path -leaf $vulnerabilityManifest))

        #loop through each vulnerability in the VulnerabilityManifest
        ForEach ($vuln in $vulns) {

            #create output directory
            $timestamp = get-date -format "yyyyMMMddThhmm"
            $vulnName = $vuln.VulnerabilityName | Get-FileNameRemoveInvalidChar
            $OutputDirectory = "$OutputDirectory\$timestamp\$vulnName"
            if (!(Test-Path $OutputDirectory)) {
                try { $null = (New-Item -Path $OutputDirectory -ItemType Directory -ErrorAction Stop)}
                catch { Write-Error $_.exception; break}
            }
            
            #Test vulnerability -- default parameters are used, which evaluate WannaCry
            [array]$allServers = Test-Vulnerability -computerName $ComputerName -KB $vuln.ApplicableHotfixes -TargetFile $vuln.TargetFile -fileVersions $vuln.FileVersions -Services $vuln.Services -verbose
            
            #create subset of server for display
            $healthyServers = $allServers.Where{ $_.FileVersionOk -eq $true -or $_.AllServicesOK -eq $true }
            $unknownServers = $allServers.Where{ $_.status -eq 'Disconnected' -or $_.status -eq 'Unknown' }
            $vulnerableServers = $allServers.Where{ $_.FileVersionOk -eq $false -or $_.AllServicesOK -eq $false }

            #if status of servers is unknown, try to ping and do other tests to get their state
            if ($unknownServers) {
                [array]$serverState = $unknownServers.ComputerName | Test-ComputerState

                $maybeDeadServers = $serverState.Where{$_.PingResponse -eq $false -and $_.DNSResponse -eq 'No DNS record' -and $_.OSviaWMI -eq 'WMI Query Failed'}
                $maybeAliveServers = $serverState.Where{$_.PingResponse -ne $false -or $_.DNSResponse -ne 'No DNS record' -or $_.OSviaWMI -ne 'WMI Query Failed'}
            }

            #output CSV files for use
            $allServersPath = "$OutputDirectory\$vulnName-AllServers_$timestamp.csv"
            $healthyServersPath = "$OutputDirectory\$vulnName-HealthyServers_$timestamp.csv"
            $unknownServersPath = "$OutputDirectory\$vulnName-UnknownServers_$timestamp.csv"
            $vulnerableServersPath = "$OutputDirectory\$vulnName-VulnerableServers_$timestamp.csv"
            $maybeDeadServersPath = "$OutputDirectory\$vulnName-MaybeDeadServers_$timestamp.csv"
            $maybeAliveServersPath = "$OutputDirectory\$vulnName-MaybeAliveServers_$timestamp.csv"

            if ($allServers) { $allServers | Export-CSV -NoTypeInformation -Path $allServersPath }
            if ($healthyServers) { $healthyServers | Export-CSV -NoTypeInformation -Path $healthyServersPath }
            if ($unknownServers) { $unknownServers | Export-CSV -NoTypeInformation -Path $unknownServersPath }
            if ($vulnerableServers) { $vulnerableServers | Export-CSV -NoTypeInformation -Path $vulnerableServersPath }
            if ($maybeDeadServers) { $maybeDeadServers | Export-CSV -NoTypeInformation -Path $maybeDeadServersPath }
            if ($maybeAliveServers) { $maybeAliveServers | Export-CSV -NoTypeInformation -Path $maybeAliveServersPath }

            #display healthyServers in green
            If ($healthyServers) {
                Write-Host -ForegroundColor Green -Object 'THE FOLLOWING SERVERS CONNECTED SUCCESSFULLY AND ARE IN A KNOWN HEALTHY STATE:'
                Write-Host -ForegroundColor Green ($healthyServers | Format-Table -AutoSize | Out-String)
                Write-Host -ForegroundColor Green -Object "Log File: $healthyServersPath`n"
            }
            else {
                Write-Host -ForegroundColor Yellow -Object "NO SERVERS WERE FOUND IN A GOOD STATE.`n"
            }

            #display unkown servers in yellow
            If ($unknownServers) {
                Write-Host -ForegroundColor Yellow -Object "SERVERS WERE FOUND IN AN UNKNOWN STATE... TESTING THEM FOR POTENTIAL DEAD/ALIVE STATUS:"
            }
            else {
                Write-Host -ForegroundColor Green -Object "NO SERVERS WERE FOUND IN AN UNKNOWN STATE.`n"
            }
            Write-Host "`n"

            #display maybe dead servers in dark gray
            if ($maybeDeadServers) {
                Write-Host -ForegroundColor DarkGray -Object 'THE FOLLOWING SERVERS MAY BE DEAD:'
                Write-Host -ForegroundColor DarkGray ($maybeDeadServers | Format-Table -AutoSize | Out-String)
                Write-Host -ForegroundColor DarkGray -Object "Log File: $maybeDeadServersPath`n"
            }
            else {
                Write-Host -ForegroundColor Green -Object "NO SERVERS WERE FOUND IN A MAYBE DEAD STATE.`n"
            }

            #display maybe alive servers in magenta
            if ($maybeAliveServers) {
                Write-Host -ForegroundColor Magenta -Object 'THE FOLLOWING SERVERS MAY BE ALIVE:'
                Write-Host -ForegroundColor Magenta ($maybeAliveServers | Format-Table -AutoSize | Out-String)
                Write-Host -ForegroundColor Magenta -Object "Log File: $maybeAliveServersPath`n"
            }
            else {
                Write-Host -ForegroundColor Green -Object "NO SERVERS WERE FOUND IN A MAYBE ALIVE STATE.`n"
            }

            #display vulnerable servers in red
            If ($vulnerableServers) {
                Write-Host -ForegroundColor Red -Object 'THE FOLLOWING SERVERS ARE IN A BAD STATE:'
                Write-Host -ForegroundColor Red ($vulnerableServers | Format-Table -AutoSize | Out-String)
                Write-Host -ForegroundColor Red -Object "Log File: $VulnerableServersPath"
            }
            else {
                Write-Host -ForegroundColor Green -Object 'NO SERVERS WERE FOUND IN A ' -NoNewline
                Write-Host -ForegroundColor Red -Object 'BAD ' -NoNewline
                Write-Host -ForegroundColor Green -Object 'STATE.'
            }

            #return all servers if passthru specified.
            if ($passthru) {Write-Output $allServers}
        }#>
    }
}

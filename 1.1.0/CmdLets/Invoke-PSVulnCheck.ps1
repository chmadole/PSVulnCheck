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
                    
                    ApplicableHotfixes = @('KB4012214','KB4012217','KB4012213','KB4012216','KB4012212','KB4012215') #https://technet.microsoft.com/library/security/MS17-010
                    
                    TargetFile = 'C:\Windows\System32\win32k.sys' #we will check this file's version
                    
                    FileVersions = @{
                        # OS Versions: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
                        # Version 6.1 - Windows 7 / Windows Server 2008R2
                        # Version 6.2 - Windows 8 / Windows server 2102
                        # Version 6.3 - Windows 8.1 / Windows Server 2012R2
                        
                        Win6_1 = '6.1.7601.23677' #https://support.microsoft.com/en-us/help/4012212/march-2007-security-only-quality-update-for-windows-7-sp1-and-windows-server-2008-r2-sp1 
                        Win6_2 = '6.2.9200.22099' #https://support.microsoft.com/en-us/help/4012217/march-2017-security-monthly-quality-rollup-for-windows-server-2012
                        Win6_3 = '6.3.9600.18603' #https://support.microsoft.com/en-us/help/4012213/march-2017-security-only-quality-update-for-windows-8-1-and-windows-server-2012-r2
                    }
                }
                #create additional hash tables here to process multiple vulns or multiple files
            )

    .EXAMPLE
        The following examples use the servers.txt file containing this code:
            server1.contoso.com
            server2.contoso.com
            server3.contoso.com
            server4.contoso.com
            server5.contoso.com
            server6.contoso.com
            server7.contoso.com
            server8.contoso.com
            server9.contoso.com
            server10.contoso.com

        And a VulnerabilityManifest.psd1 file containing this code:
            @(
                @{
                    VulnerabilityName = 'WannaCry'
                    
                    ApplicableHotfixes = @('KB4012214','KB4012217','KB4012213','KB4012216','KB4012212','KB4012215')
                    
                    TargetFile = 'C:\Windows\System32\win32k.sys'
                    
                    FileVersions = @{
                        Win6_1 = '6.1.7601.23677'
                        Win6_2 = '6.2.9200.22099'
                        Win6_3 = '6.3.9600.18603'
                    }
                }
            )

    .EXAMPLE
        Invoke-PSVulnCheck -InputObject (Get-Content C:\Users\<Username>\Documents\servers.txt) `
        -VulnerabilityManifest C:\Users\<Username>\Documents\VulnerabilityManifest.psd1

            Pulls server names from a flat file with server names 1 per line and checks for the
            vulnerability defined by VulnerabilityManifest.psd1.
            Writes one to six output files to C:\Users\<Username>\Documents\PSVulnCheck (depending on
            the state of the scanned items).
            Displays color coded output to the screen.

    .EXAMPLE
        $results = Invoke-PSVulnCheck -ComputerName (Get-Content C:\Users\<Username>\Documents\servers.txt) `
        -VulnerabilityManifest C:\Users\<Username>\Documents\VulnerabilityManifest.psd1 `
        -OutputDirectory 'C:\Users\<Username>\Documents\AssetCheck' -passthru
            Same as above except results will be placed in C:\Users\<Username>\Documents\AssetCheck
            An array of [PSCustomObjects] will be returned and stored in the variable $results for you to
            utilize.

    .EXAMPLE
        Get-Content C:\Users\<Username>\Documents\servers.txt |  Invoke-PSVulnCheck
            Same as above, but uses pipeline to import servers.  Note, due to the use of invoke-parallel,
            you cannot specify the value from pipeline by property name.  You must pass in an array of
            strings [string[]].
            The default Vulnerability manifest file is used ("$PSScriptRoot\VulnerabilityManifest.psd1")
            for the WannaCry vulnerability from 2017.

    .EXAMPLE
        The following example use the serversCSV.csv file containing this code:
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

        (Import-Csv C:\Temp\serversCSV.csv).server | Invoke-PSVulnCheck
            This functions the same as the previous example, but provides more insight in how to pass
            a named property into the command.

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
        Function Remove-InvalidFileNameChars {
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
            $vulnName = $vuln.VulnerabilityName | Remove-InvalidFileNameChars
            $OutputDirectory = "$OutputDirectory\$timestamp\$vulnName"
            if (!(Test-Path $OutputDirectory)) {
                try { $null = (New-Item -Path $OutputDirectory -ItemType Directory -ErrorAction Stop)}
                catch { Write-Error $_.exception; break}
            }
            
            #Test vulnerability -- default parameters are used, which evaluate WannaCry
            [array]$allServers = Test-Vulnerability -computerName $ComputerName -KB $vuln.ApplicableHotfixes -TargetFile $vuln.TargetFile -fileVersions $vuln.FileVersions
            
            #create subset of server for display
            $healthyServers = $allServers.Where{ $_.FileVersionOk -eq $true }
            $unknownServers = $allServers.Where{ $_.status -eq 'Disconnected' -or $_.status -eq 'Unknown' }
            $vulnerableServers = $allServers.Where{ $_.FileVersionOk -eq $false }

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

            if ($allServers) { $allServers        | Export-CSV -NoTypeInformation -Path $allServersPath }
            if ($healthyServers) { $healthyServers    | Export-CSV -NoTypeInformation -Path $healthyServersPath }
            if ($unknownServers) { $unknownServers    | Export-CSV -NoTypeInformation -Path $unknownServersPath }
            if ($vulnerableServers) { $vulnerableServers | Export-CSV -NoTypeInformation -Path $vulnerableServersPath }
            if ($maybeDeadServers) { $maybeDeadServers  | Export-CSV -NoTypeInformation -Path $maybeDeadServersPath }
            if ($maybeAliveServers) { $maybeAliveServers | Export-CSV -NoTypeInformation -Path $maybeAliveServersPath }

            #display healthyServers in green
            If ($healthyServers) {
                Write-Host -ForegroundColor Green -Object 'THE FOLLOWING SERVERS CONNECTED SUCCESSFULLY AND ARE IN A KNOWN HEALTHY STATE:'
                Write-Host -ForegroundColor Green ($healthyServers | Select-Object -Property ComputerName, OSVersion, FileVersionOk, TargetFile, TargetFileVersion, ActualFileVersion, Patched, InstalledKBs |  Format-Table -AutoSize | Out-String)
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
                Write-Host -ForegroundColor Magenta ($maybeAliveServers | Select -Property * | Format-Table -AutoSize | Out-String)
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

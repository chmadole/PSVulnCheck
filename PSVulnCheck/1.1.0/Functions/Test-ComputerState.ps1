#Helper function for PSVulnCheck

Function Test-ComputerState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [string[]] $computerName,
        
        [string] $logfile
    )

    Begin{}
    #Process{} - omitted to facilitate Invoke-Parallel Processing
    End {

        #set $input for when using -computername instead of the pipeline
        if (!$input) {$input = $ComputerName}

        if (-not $logfile ) {$logfile = "$env:USERPROFILE\$($MyInvocation.MyCommand)-InvokeParallel.log"}

        $input | Invoke-Parallel -LogFile $logFile -Throttle 50 -RunspaceTimeout 600 {
            $iComputerName = $_
            $output        = [PSCustomObject]@{ComputerName = $iComputerName}

            #Ping it
            $pingResponse = $null
            try     { $pingResponse = (Test-Connection -ComputerName $iComputerName -Count 2 -Quiet -ErrorAction Stop) } 
            catch   { $pingResponse = $_.exception }
            finally { $output | Add-Member -MemberType NoteProperty -Name PingResponse -Value $pingResponse}
            
            #resolve DNS
            $DNSResponse = $null
            try     { $DNSResponse = ([Net.DNS]::GetHostEntry($iComputerName)).AddressList } 
            catch   { $DNSResponse = if ($_.exception.message -match 'No such host is known') {'No DNS record'} else {$_.exception.message} }
            finally { $output | Add-Member -MemberType NoteProperty -Name DNSResponse -Value $DNSResponse}

            #try to grab a win32 piece of info
            try {
                $WMIObj = [WMISearcher]''   
                $WMIObj.options.timeout = '0:0:10'  
                $WMIObj.scope.path = "\\$iComputerName\root\cimv2"   
                $WMIObj.query = "SELECT Caption,OSArchitecture,Version,ServicePackMajorVersion FROM Win32_OperatingSystem"   
                $OS = $WMIObj.get() | ForEach-Object {"$($_.Caption) SP$($_.ServicePackMajorVersion) $($_.OSArchitecture) ($($_.Version))"}
            }
            catch   { $OS = if ($_.exception -match 'Exception calling "Get" with "0"') {'WMI Query Failed'} else {$_.exception } }
            finally {  $output | Add-Member -MemberType NoteProperty -Name 'OSviaWMI' -Value $OS}
            
            #try getting info from the box using psexec
            #psexec -s 

            Write-Output $output
        }

        remove-item -Path $logfile
    }
}

<#
$iComputerName = '019D-CO1-SSQ04.019D.MGD.MSFT.NET'
$iComputerName = '025D-BN1-PAS01.025d.mgd.msft.net' #good
$iComputerName = (import-csv D:\chmadole\WannaCrySupplementals\UnknownServers.csv | select -first 10).computername

remove-module psvulncheck ; import-module D:\chmadole\modules\PSVulnCheck\PSVulnCheck\1.1.0\PSVulnCheck.psd1
test-computerstate -computername (import-csv D:\chmadole\WannaCrySupplementals\UnknownServers.csv | select -first 50).computername | format-table -autosize
#>
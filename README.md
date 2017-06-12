## Synopsis

A PowerShell module to check the Windows operating system for a particular vulnerability (such as 2017's WannaCry vuln) by searching for successfully applied patches (described by KB number) or by checking the version on a particular file.

## Code Example

### 1. First you'll need to define the vulnerability that you're looking for:
Start with virus definition manifest file like this with a `.psd1` extention, named, for example,  `vuln.psd1`.

The following definition will find vulnerability for the ransomware [WannaCry][WannaCryLink].
```
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
```
*For more information on sourcing the information for the manifest file, view the [VulnerabilityManifest.psd1](./1.1.0/VulnerabilityManifest.psd1) file.*


### 2. Next, execute PSVulnCheck by calling the Invoke-PSVulnCheck cmdlet with the vuln.psd1 manifest that you created above.

  1. The following code checks server1 and server2 for the vulnerability specified in the vuln.psd1 file.  Writes 4 output files to C:\Temp\PSVulnCheck.  Displays color coded output screen.

         Invoke-PSVulnCheck -ComputerName @('server1','server2') -Vuln vuln.psd1

  2. The following code pulls a list of servers (1 [FQDN](https://www.google.com/search?q=FQDN&ie=utf-8&oe=utf-8) per line) using the pipeline and checks for vulnerability.  Note, due to the use of invoke-parallel to speed processing, you cannot [specify the value from pipeline by property name](https://blogs.technet.microsoft.com/heyscriptingguy/2013/03/25/learn-about-using-powershell-value-binding-by-property-name/).  You must pass in an array of strings `[string[]]`.

         Get-Content C:\Temp\servers.txt |  Invoke-PSVulnCheck

  3. Same as above except results will be placed in `C:\Temp\AssetCheck` An array of  `[PSCustomObjects[]]` will be returned and stored in the variable $results for you to utilize.
    
         $results = Get-Content C:\Temp\servers.txt | Invoke-PSVulnCheck -OutputDirectory 'C:\Temp\AssetCheck' -passthru

  4. The following example uses the `servers.csv` file containing this code:

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

  5. This functions the same as the previous example, but provides more insight in how to pass a named property into the command.

         (Import-Csv C:\Temp\servers.csv).server | Invoke-PSVulnCheck

## Motivation

When the big malware of the year happens, everyone enjoys the scramble of validating that their assets are not vulnerable.  Inevitably in large environments, you'll find assets that fall out of your standard scanning and patching, or you'd like to have a separate or redundant evaluation.  PSVulnCheck was created as a tool to fulfill this need.  At the time of its development, [WannaCry][WannaCryLink] was the malware of the moment, hence the examples are for that vulnerability.  However, when the next virus comes along, sub in the effected file and the minimum required version, and the KB numbers which remediate the item.  The tool should operate for any vulnerability.

## Installation

1. `Import-Module <FullPathToModule>\<moduleVersion>\PSVulnCheck.psd1`

    or

1) Copy the complete PSVulnCheck module directory to `C:\Program Files\WindowsPowerShell\Modules`
2) Execute `Import-Module PSVulnCheck`

## API Reference
This readme.md file serves as one API reference to the module.

Also, from the PowerShell prompt you can access using standard help:

    PS> Get-Help Invoke-PSVulnCheck

## Tests

No tests have been written yet for the module.

## Contributors

Contributions and constructive criticism are always welcome.  Please use the GitHub Issues page for problems or create a pull request for modifications/improvements.

## License

MIT License

Copyright (c) 2017 Microsoft SharePoint Online

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


[WannaCryLink]: https://en.wikipedia.org/wiki/WannaCry_ransomware_attack
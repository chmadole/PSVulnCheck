## Synopsis

A PowerShell module to check the Windows operating system for a particular vulnerability (such as 2017's WannaCry vuln) by searching for successfully applied patches (described by KB number) or by checking the version on a particular file.

## Code Example
    Invoke-PSVulnCheck -ComputerName (Get-Content C:\Temp\servers.txt)
Pulls server names from a flat file with server names 1 per line and checks for vulnerability.
Writes 4 output files to C:\Temp\PSVulnCheck
Displays color coded output screen.

    $results = Invoke-PSVulnCheck -ComputerName (Get-Content C:\Temp\servers.txt) -OutputDirectory 'C:\Temp\AssetCheck' -passthru
Same as above except results will be placed in `C:\Temp\AssetCheck`
An array of `[PSCustomObjects[]]` will be returned and stored in the variable $results for you to
utilize.

    Get-Content C:\Temp\servers.txt |  Invoke-PSVulnCheck
Same as above, but uses pipeline to import servers.  Note, due to the use of invoke-parallel,
you cannot specify the value from pipeline by property name.  You must pass in an array of
strings `[string[]]`.

The following example uses the `serversCSV.csv` file containing this code:
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
This functions the same as the previous example, but provides more insight in how to pass a named property into the command.
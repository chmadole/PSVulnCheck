There are two ways to use this module:

	PS> Import-Module C:\pathToModule\WannaCryVunerabilityCheck.psd1

	-- or --

	1) Copy this module director to C:\Program Files\WindowsPowerShell\Modules
	2) PS> Import-Module PSVulnCheck

To get help syntax, type:
	PS> Get-Help PSVulnCheck

Alternatively, here is the common syntax for utilizing the module:

SYNOPSIS
    Function to check for Wanna Cry vulnerability on Server 2008R2, 2012, & 2012 R2
DESCRIPTION
    Function to check for Wanna Cry vulnerability on Server 2008R2, 2012, & 2012 R2
        Examines the file version of C:\Windows\System32\win32k.sys for a new enough version
        Examines whether the patches to remediate Wanna Cry have been installed
        Outputs color output to the screen for easy viewing
        Outputs csv files to for All, Healthy, Unknown, and Vulnerable Servers
PARAMETER ComputerName
    Computer FQDNs (Fully Qualified Domain Names) to execute code vulnerability check against.
PARAMETER OutputDirectory
    Directory to output the files to C:\Temp\PSVulnCheck
PARAMETER Passthru
    By default, you will see output on the screen and in the files.  If you want an object returned
    that you can manipulate in PowerShell, add the -passthru to return an object containing all servers.
EXAMPLE
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

EXAMPLE
    Invoke-PSVulnCheck -ComputerName (Get-Content C:\Temp\servers.txt)
        Pulls server names from a flat file with server names 1 per line and checks for vulnerability.
        Writes 4 output files to C:\Temp\PSVulnCheck
        Displays color coded output screen.

EXAMPLE
    $results = Invoke-PSVulnCheck -ComputerName (Get-Content C:\Temp\servers.txt) `
    -OutputDirectory 'C:\Temp\AssetCheck' -passthru
        Same as above except results will be placed in C:\Temp\AssetCheck
        An array of [PSCustomObjects] will be returned and stored in the variable $results for you to
        utilize.

EXAMPLE
    Get-Content C:\Temp\servers.txt |  Invoke-PSVulnCheck
        Same as above, but uses pipeline to import servers.  Note, due to the use of invoke-parallel,
        you cannot specify the value from pipeline by property name.  You must pass in an array of
        strings [string[]].

EXAMPLE
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

FUNCTIONALITY
    PowerShell Language
NOTES
    Credit to Warren Frame for Invoke-Parallel: https://github.com/RamblingCookieMonster/Invoke-Parallel
    Credit to SharePoint Online 365 PAV team for assistance.

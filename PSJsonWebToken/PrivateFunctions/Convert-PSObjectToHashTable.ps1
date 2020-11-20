function Convert-PSObjectToHashTable
{
<#
    .SYNOPSIS
        Converts a PSObject to a hash table.
    .DESCRIPTION
        Converts a System.Management.Automation.PSObject to a System.Collections.Hashtable.
    .PARAMETER InputObject
         Specifies the PSObject to send down the pipeline.
    .EXAMPLE
        Get-Content -Path 'C:\groups.json' -Raw | ConvertFrom-Json | Convert-PSObjectToHashTable

        Gets the content from a JSON file, converts it to a PSObject, and finally to a hash table.
    .EXAMPLE
        $psObject = Get-ADUser -Identity $env:USERNAME -Properties * | Select-Object -Property Name, Description, UserPrincipalName
        Convert-PSObjectToHashTable -InputObject $psObject

        Converts the resulting PSObject from the Select-Object cmdlet into a hash table.
    .INPUTS
        System.Management.Automation.PSObject

            A PSObject is received by the InputObject parameter.
    .OUTPUTS
        System.Collections.Hashtable
    .LINK
        Get-Content
        ConvertFrom-Json
#>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    Param (
            [Parameter(
                Position = 0,
                Mandatory = $true,
                ValueFromPipeline = $true
            )][ValidateNotNullOrEmpty()]
            [System.Management.Automation.PSObject]$InputObject
    )

     PROCESS
     {
        $hashTable = @{}

        $InputObject.PSObject.Properties | ForEach-Object {
            $hashTable.Add($_.Name, $_.Value)
        }

        Write-Output -InputObject $hashTable
     }
}
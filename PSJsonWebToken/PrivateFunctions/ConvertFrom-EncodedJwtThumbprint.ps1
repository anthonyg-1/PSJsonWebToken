function ConvertFrom-EncodedJwtThumbprint
{
    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)][String]$EncodedThumbprint
    )
    PROCESS
    {
        [string]$decodedThumbprint = ""

        try
        {
            [byte[]]$x509CertThumbprintBytes = ConvertFrom-Base64UrlEncodedString -InputString $EncodedThumbprint -AsBytes

            $decodedThumbprint = [BitConverter]::ToString($x509CertThumbprintBytes).Replace("-", "")
        }
        catch
        {
            Write-Error -Exception ([ArgumentException]::new("Unable to decode JWT signing certificate thumbprint.")) -Category InvalidArgument -ErrorAction Stop
        }

        return $decodedThumbprint
    }
}
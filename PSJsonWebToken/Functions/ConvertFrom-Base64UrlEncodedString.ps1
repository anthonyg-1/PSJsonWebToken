function ConvertFrom-Base64UrlEncodedString
{
<#
    .SYNOPSIS
        Decodes a base 64 URL encoded string.
    .DESCRIPTION
        Decodes a base 64 URL encoded string such as a JWT header or payload.
    .PARAMETER InputString
        The string to be base64 URL decoded.
    .PARAMETER AsBytes
        Instructions this function to return the result as a byte array as opposed to a default string.
    .EXAMPLE
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | ConvertFrom-Base64UrlEncodedString

		Decodes a JWT header.
    .INPUTS
        System.String

            A string is received by the InputString parameter.
    .OUTPUTS
        System.String

            Returns a base 64 URL decoded string for the given input.
    .LINK
        https://tools.ietf.org/html/rfc4648#section-5
#>

    [CmdletBinding()]
    [OutputType([System.String], [System.Byte[]])]
    [Alias('b64d', 'Decode')]
    param (
        [Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$InputString,

        [Parameter(Position=1,Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false)]
        [switch]$AsBytes
    )

    BEGIN
    {
        $argumentExceptionMessage = "The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters."
        $ArgumentException = New-Object -TypeName System.ArgumentException -ArgumentList $argumentExceptionMessage
    }
    PROCESS
    {
        try
        {
            $output = $InputString
            $output = $output.Replace('-', '+') # 62nd char of encoding
            $output = $output.Replace('_', '/') # 63rd char of encoding

            switch ($output.Length % 4) # Pad with trailing '='s
            {
                0 { break }# No pad chars in this case
                2 { $output += "=="; break } # Two pad chars
                3 { $output += "="; break } # One pad char
                default { Write-Error -Exception ([ArgumentException]::new("Illegal base64url string!")) -Category InvalidArgument -ErrorAction Stop }
            }

            # Byte array conversion:
            [byte[]]$convertedBytes = [Convert]::FromBase64String($output)
            if ($PSBoundParameters.ContainsKey("AsBytes"))
            {
                return $convertedBytes
            }
            else
            {
                # String to be returned:
                $decodedString = [System.Text.Encoding]::ASCII.GetString($convertedBytes)
                return $decodedString
            }
        }
        catch
        {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }
    }
}
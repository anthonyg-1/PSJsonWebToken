function ConvertTo-Base64UrlEncodedString
{
<#
    .SYNOPSIS
        Base 64 URL encodes an input string.
    .DESCRIPTION
        Base 64 URL encodes an input string required for the payload or header of a JSON Web Token (JWT).
    .PARAMETER InputString
        The string to be base64 URL encoded.
    .PARAMETER Bytes
        The byte array derived from a string to be base64 URL encoded.
    .EXAMPLE
        $jwtPayload = '{"role":"Administrator","sub":"first.last@company.com","jti":"545a310d890F47B9b1F5dc104f782ABD","iat":1551286711,"nbf":1551286711,"exp":1551287011}'
        ConvertTo-Base64UrlEncodedString -InputString $jwtPayload

        Base 64 URL encodes a JSON value.
    .INPUTS
        System.String

            A string is received by the InputString parameter.
    .OUTPUTS
        System.String

            Returns a base 64 URL encoded string for the given input.
    .LINK
        https://tools.ietf.org/html/rfc4648#section-5
#>

    [CmdletBinding()]
    [Alias('b64e', 'Encode')]
    [OutputType([System.String])]
    param (
        [Parameter(Position=0,ParameterSetName="String",Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$InputString,

        [Parameter(Position=1,ParameterSetName="Byte Array",Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false)]
        [byte[]]$Bytes
    )

    PROCESS
    {
        [string]$base64UrlEncodedString = ""

        if ($PSBoundParameters.ContainsKey("Bytes"))
        {
            try
            {

                $output = [Convert]::ToBase64String($Bytes)
                $output = $output.Split('=')[0] # Remove any trailing '='s
                $output = $output.Replace('+', '-') # 62nd char of encoding
                $output = $output.Replace('/', '_') # 63rd char of encoding

                $base64UrlEncodedString = $output
            }
            catch
            {
                $ArgumentException = New-Object -TypeName System.ArgumentException -ArgumentList $_.Exception.Message
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }
        }
        else
        {
            try
            {
                $encoder = [System.Text.UTF8Encoding]::new()

                [byte[]]$inputBytes = $encoder.GetBytes($InputString)

                $base64String = [Convert]::ToBase64String($inputBytes)

                [string]$base64UrlEncodedString = ""
                $base64UrlEncodedString = $base64String.Split('=')[0] # Remove any trailing '='s
                $base64UrlEncodedString = $base64UrlEncodedString.Replace('+', '-'); # 62nd char of encoding
                $base64UrlEncodedString = $base64UrlEncodedString.Replace('/', '_'); # 63rd char of encoding
            }
            catch
            {
                $ArgumentException = New-Object -TypeName System.ArgumentException -ArgumentList $_.Exception.Message
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }
        }

        return $base64UrlEncodedString
    }
}

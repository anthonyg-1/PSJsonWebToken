function ConvertTo-JwtPart {
    <#
    .SYNOPSIS
        Converts an object to a base 64 URL encoded compressed JSON string.
    .DESCRIPTION
        Converts an object to a base 64 URL encoded compressed JSON string. Useful when constructing a JWT header or payload from a InputObject prior to serialization.
    .PARAMETER InputObject
        Specifies the object to convert to a JWT part. Enter a variable that contains the object, or type a command or expression that gets the objects. You can also pipe an object to ConvertTo-JwtPart.
    .EXAMPLE
        $jwtHeader = @{typ="JWT";alg="HS256"}
        $encodedHeader = $jwtHeader | ConvertTo-JwtPart

        Constructs a JWT header from the hashtable defined in the $jwtHeader variable, serializes it to JSON, and base 64 URL encodes it.
    .EXAMPLE
        $header = @{typ="JWT";alg="HS256"}
        $payload = @{sub="someone.else@company.com";title="person"}

        $encodedHeader = $header | ConvertTo-JwtPart
        $encodedPayload = $payload | ConvertTo-JwtPart

        $jwtSansSignature = "{0}.{1}" -f $encodedHeader, $encodedPayload

        $hmacSignature = New-JwtHmacSignature -JsonWebToken $jwtSansSignature -Key "secret"

        $jwt = "{0}.{1}" -f $jwtSansSignature, $hmacSignature

        Constructs a header and payload from InputObjects, serializes and encodes them and obtains an HMAC signature from the resulting joined values.
    .INPUTS
        System.Object
    .OUTPUTS
        System.String
    .LINK
        New-JwtHmacSignature
        New-JsonWebToken
        Test-JsonWebToken
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNullOrEmpty()][System.Object]$InputObject
    )
    BEGIN {
        $argumentExceptionMessage = "Unable to serialize and base64 URL encode passed InputObject."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $argumentExceptionMessage
    }
    PROCESS {
        [string]$base64UrlEncodedString = ""
        try {
            $base64UrlEncodedString = $InputObject | ConvertTo-Json -Depth 25 -Compress | ConvertTo-Base64UrlEncodedString
        }
        catch {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        return $base64UrlEncodedString
    }
}

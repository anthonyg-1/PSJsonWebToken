function Get-JsonWebTokenSignature {
    <#
    .SYNOPSIS
        Gets the JSON Web Token signature from the passed JWT.
    ..DESCRIPTION
        Deserializes a JSON Web Token payload to a byte array by default. Optionally the original base 64 URL encoded signature can be returned via the AsEncodedString parameter.
    .PARAMETER JsonWebToken
        Specifies the The JSON Web Token to get the signature from.
    .PARAMETER AsEncodedString
        Returns the signature as a base 64 URL encoded string as opposed to the decoded value as a byte array.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        $jwt | Get-JsonWebTokenSignature

        Returns the signature from the passed JWT as a byte array.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Get-JsonWebTokenSignature -JsonWebToken $jwt -AsEncodedString

        Returns the encoded signature from the passed JWT.
    .INPUTS
        System.String

            A String is received by the JsonWebToken parameter.
    .OUTPUTS
        System.Byte or System.String
    .LINK
	New-JsonWebToken
        Test-JsonWebToken
        Get-JsonWebTokenHeader
        Get-JsonWebTokenPayload
#>
    [CmdletBinding()]
    [Alias('gjwtsig')]
    [OutputType([System.String], [System.Byte[]])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateLength(16, 8192)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $false, Position = 1)][Alias("AsIs")][switch]$AsEncodedString
    )

    BEGIN {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS {
        [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken -VerifySignaturePresent
        if (-not($isValidJwt)) {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        $jwtSignature = $JsonWebToken.Split(".")[2]

        if ($PSBoundParameters.ContainsKey("AsEncodedString")) {
            return $jwtSignature
        }
        else {
            $jwtSignatureByteArray = ConvertFrom-Base64UrlEncodedString -InputString $jwtSignature -AsBytes
            return $jwtSignatureByteArray
        }
    }
}

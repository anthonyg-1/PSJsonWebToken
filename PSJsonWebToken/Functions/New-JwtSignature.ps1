function New-JwtSignature
{
<#
    .SYNOPSIS
        Generates an RSA or HMAC signature for the header and payload of a JSON Web Token.
    .DESCRIPTION
        Generates an RSA or HMAC signature for the incoming value in the JsonWebToken parameter. The value passed to the JsonWebToken parameter should contain only the header and payload of a JSON Web Token with the appropriate algorithm being defined in the "alg" claim of the header.
    .PARAMETER JsonWebToken
        Contains the JWT minus the signature (encoded header and payload seperated by a period) to generate the HMAC signature for.
    .PARAMETER HashAlgorithm
        The hash algorithim for the signature. Acceptable values are SHA256, SHA384, and SHA512.
    .PARAMETER SigningCertificate
        The certificate containing the private key that will sign the JSON Web Token.
    .PARAMETER Key
        The secret key used to generate the HMAC signature.
    .PARAMETER SkipJwtStructureTest
        Skips testing the incoming JWT for structural validity.
    .EXAMPLE
        $jwtSansSig = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ"
        $myCert = Get-Item -Path Cert:\CurrentUser\my\690F0B1D51BD88AEEA1E374B22BBA7BDAB1BE84B
        $rsaSig = New-JwtSignature -JsonWebToken $jwtSansSig -HashAlgorithm SHA256 -SigningCertificate $myCert
        $jws = "{0}.{1}" -f $jwtSansSig, $rsaSig

        Produces an SHA256 RSA signature for the JWT in the $jwtSansSig variable and constructs a JSON Web Signature (JWS) defined in the $jws variable.
    .EXAMPLE
        $jwtSansSig = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"
        $secret = "super secret key!"
        $hmacSig = New-JwtSignature -JsonWebToken $jwtSansSig -Key $secret -HashAlgorithm SHA256
        $jws = "{0}.{1}" -f $jwtSansSig, $hmacSig

        Validates the two part passed JWT, produces an HMACSHA256 signature for the JWT in the $jwtSansSig variable, and constructs a JSON Web Signature (JWS) defined in the $jws variable.
    .NOTES
        The resulting HMAC SHA-256, SHA-384, or SHA-512 algorithm is base64url encoded to be compliant with JWT standard RFC 7519.
    .OUTPUTS
        System.String

            An digital signature is returned as a base64 URL encoded string.
    .LINK
        https://tools.ietf.org/html/rfc7519
        https://en.wikipedia.org/wiki/RSA_(cryptosystem)
		https://en.wikipedia.org/wiki/HMAC
#>
    [CmdletBinding()]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
        [ValidateLength(16,131072)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory=$false,Position=1)]
        [ValidateSet("SHA256","SHA384","SHA512")]
        [String]$HashAlgorithm="SHA256",

        [Parameter(Mandatory=$true,ParameterSetName="RSA",Position=2)][Alias("Certificate", "Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = "HMAC", Position = 3)]
        [ValidateLength(1, 32768)]
        [String]$Key,

        [Parameter(Mandatory=$false,ValueFromPipeline=$false,Position=4)][Switch]$SkipJwtStructureTest
        )

    BEGIN
    {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS
    {
        [string]$jwtSignature = ""

        if (-not($PSBoundParameters.ContainsKey("SkipJwtStructureTest")))
        {
            [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken

            if (-not($isValidJwt))
            {
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }
        }

        if ($PSCmdlet.ParameterSetName -eq "HMAC")
        {
            [byte[]]$secretBytes = [Encoding]::ASCII.GetBytes($Key)

            [HMAC]$hmacSha = $null
            switch ($HashAlgorithm)
            {
                "SHA256" { $hmacSha = [HMACSHA256]::new($secretBytes) }
                "SHA384" { $hmacSha = [HMACSHA384]::new($secretBytes) }
                "SHA512" { $hmacSha = [HMACSHA512]::new($secretBytes) }
                default { $hmacSha = [HMACSHA256]::new($secretBytes) }
            }

            $hashBytes = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($JsonWebToken))

            $jwtSignature = ConvertTo-Base64UrlEncodedString -Bytes $hashBytes

            $hmacSha.Dispose()
        }
        else
        {
            try
            {
                $jwtSignature = New-JwtRsaSignature -JsonWebToken $JsonWebToken -SigningCertificate $SigningCertificate -HashAlgorithm $HashAlgorithm
            }
            catch
            {
                $cryptographicExceptionMessage = $_.Exception.Message
                $CryptographicException = New-Object -TypeName System.Security.Cryptography.CryptographicException -ArgumentList $cryptographicExceptionMessage
                Write-Error -Exception $CryptographicException -Category SecurityError -ErrorAction Stop
            }
        }

        return $jwtSignature
    }
}

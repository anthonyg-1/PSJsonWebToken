function Test-JwtSignature
{
<#
    .SYNOPSIS
        Validates a JSON Web Token digital signature.
    .DESCRIPTION
        Validates a JSON Web Token digital signature only (no payload) for either RSA or HMAC signed JSON Web Tokens.
    .PARAMETER JsonWebToken
        The JSON Web Token containing the digital signature to be verified.
    PARAMETER HashAlgorithm
        The RSA hash algorithim for the signature. Acceptable values are SHA256, SHA384, and SHA512. Default value is SHA256.
    .PARAMETER VerificationCertificate
        The certificate that will be used to verify the signature of the JSON Web Token. The private key is NOT needed for signature verification.
    .PARAMETER Key
        This is the secret key used to generate an HMAC signature.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4QzVkRTlFMDNBNTQ0MDVBQkI2QmEyNDJENjI5MDU0MiIsImlhdCI6MTU5MjU4MTA4OSwiZXhwIjoxNTkyNTgxMzg5LCJzdWIiOiJtZUBjb21wYW55LmNvbSJ9.PkfNMxLIk0qaynr373qxgWR8lTNE5BLApFYhcG3TpK0"
        Test-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key "secret"

        Verifies a digital signature for an HAMC signed JSON Web Token against a key with a value of 'secret' (minus the quotes).
	.EXAMPLE
        $cert = Get-Item -Path "Cert:\CurrentUser\My\B31F009EEEEDDFAE34E977626E5A902600CF118C"
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InN4OEFudTd0MzY0MDZYZGlibHFRSmdEUEVZdyIsIng1dCI6InN4OEFudTd0MzY0MDZYZGlibHFRSmdEUEVZdyJ9.eyJzdWIiOiJtZUBjb21wYW55LmNvbSIsImp0aSI6Ijk4NWQyNGNDOTZDMjQxMTA5N0E3NjAzMGY1OTM4RGQzIiwiaWF0IjoxNTkyNTgwOTA1LCJuYmYiOjE1OTI1ODA5MDUsImV4cCI6MTU5MjU4MTIwNX0.whJap3yJIYLIZ4BrK4tVHQVARGstI_omkoo2odOaSpTXZRh104Kyv7J3kiRPaNWKM7t_rpEVylmX-rzY_k_-d7auysVgQL2d-xNa8ZJGmjEemniPy2qRjbpdKDONlija7sbt_7E2n6_0kiwOiu31NemVr1EoWnpGLQeSfgjExuQPHatoKmi5UfijG0P4pWeo3xYyukYE14XOVGYI0ym3yl7gh7YUq9YkKZHvnMulzUoXWImZQ3_0ihC4CwD7QfqKbBuYGCAFtfJ55WHc_iX9EjgVS69aPLIciQmRtvr-xkVG4QApKTLb5NS5dJHKwVxvDojb2OBH5bQM5PMGxpRcIA"
        Test-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -VerificationCertificate $cert

        Verifies a digital signature for an RSA signed JSON Web Token against a certificate with thumbprint B31F009EEEEDDFAE34E977626E5A902600CF118C.
    .OUTPUTS
        System.Boolean
    .LINK
        https://tools.ietf.org/html/rfc7515
		https://tools.ietf.org/html/rfc7519
        New-JwtSignature
#>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=0)]
        [ValidateLength(16,8192)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Position=2,Mandatory=$true,ParameterSetName="RSA")]
        [Parameter(Position=2,Mandatory=$true,ParameterSetName="HMAC")]
        [ValidateSet("SHA256","SHA384","SHA512")]
        [String]$HashAlgorithm,

        [Parameter(Mandatory=$true,ParameterSetName="RSA",Position=2)][Alias("Certificate", "Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$VerificationCertificate,

        [Parameter(Mandatory=$true,ParameterSetName="HMAC",Position=3)]
        [ValidateNotNullOrEmpty()]
        [String]$Key
        )

        BEGIN
        {
            $decodeExceptionMessage = "Unable to decode JWT."
            $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
        }
        PROCESS
        {
            [bool]$signatureVerifies = $false

            [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken -VerifySignaturePresent

            if (-not($isValidJwt))
            {
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }

            $jwtHeader = Get-JsonWebTokenHeader -JsonWebToken $JsonWebToken -AsEncodedString
            $jwtPayload = Get-JsonWebTokenPayload -JsonWebToken $JsonWebToken -AsEncodedString
            $jwtSig = Get-JsonWebTokenSignature -JsonWebToken $JsonWebToken -AsEncodedString

            $jwt = "{0}.{1}" -f $jwtHeader, $jwtPayload

            if ($PSCmdlet.ParameterSetName -eq "HMAC")
            {
                [string]$hmacSig = ""
                try
                {
                    $hmacSig = New-JwtSignature -JsonWebToken $jwt -Key $Key -HashAlgorithm $HashAlgorithm -ErrorAction Stop
                }
                catch
                {
                    $signatureExceptionMessage = "Unable to generate signature for given header and payload."
                    $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $signatureExceptionMessage
                    Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
                }

                if ($hmacSig -eq $jwtSig)
                {
                    $signatureVerifies = $true
                }
            }
            else
            {
                if ($null -ne $VerificationCertificate.PrivateKey.KeyExchangeAlgorithm)
				{
					Write-Warning -Message "It is not necessary to perform signature verification with a certificate that has private key!"
				}

                try
                {
                    $signatureVerifies = Test-JwtRsaSignature -JsonWebToken $JsonWebToken -VerificationCertificate $VerificationCertificate -HashAlgorithm $HashAlgorithm
                }
                catch
                {
                    $signatureVerifies = $false
                }
            }

            return $signatureVerifies
        }
}
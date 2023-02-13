function Test-JwtSignature {
    <#
    .SYNOPSIS
        Validates a JSON Web Token digital signature.
    .DESCRIPTION
        Validates a JSON Web Token digital signature only (no payload) for either RSA or HMAC signed JSON Web Tokens.
    .PARAMETER JsonWebToken
        The JSON Web Token containing the digital signature to be verified.
    .PARAMETER HashAlgorithm
        The RSA hash algorithm for the signature. Acceptable values are SHA256, SHA384, and SHA512.
    .PARAMETER VerificationCertificate
        The certificate that will be used to verify the signature of the JSON Web Token. The private key is NOT needed for signature verification.
    .PARAMETER Key
        This is the secret key used to generate an HMAC signature.
    .PARAMETER SecureKey
        The secret key used to validate an HMAC signature expressed as a System.Security.SecureString.
    .PARAMETER JsonWebKey
        The JSON Web Key (X509 certificate public key) to verify the signature of the JSON Web Token per RFC 7517.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4QzVkRTlFMDNBNTQ0MDVBQkI2QmEyNDJENjI5MDU0MiIsImlhdCI6MTU5MjU4MTA4OSwiZXhwIjoxNTkyNTgxMzg5LCJzdWIiOiJtZUBjb21wYW55LmNvbSJ9.PkfNMxLIk0qaynr373qxgWR8lTNE5BLApFYhcG3TpK0"
        Test-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key "secret"

        Verifies a digital signature for an HMAC-SHA256 signed JSON Web Token against a key with a value of 'secret' (minus the quotes).
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4QzVkRTlFMDNBNTQ0MDVBQkI2QmEyNDJENjI5MDU0MiIsImlhdCI6MTU5MjU4MTA4OSwiZXhwIjoxNTkyNTgxMzg5LCJzdWIiOiJtZUBjb21wYW55LmNvbSJ9.PkfNMxLIk0qaynr373qxgWR8lTNE5BLApFYhcG3TpK0"
        $secureKey = "secret" | ConvertTo-SecureString -AsPlainText -Force
        Test-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -SecureKey $secureKey

        # Verifies a digital signature for an HMAC-SHA256 signed JSON Web Token against a key with a value of 'secret' expressed as a System.Security.SecureString.
	.EXAMPLE
        $cert = Get-Item -Path "Cert:\CurrentUser\My\B31F009EEEEDDFAE34E977626E5A902600CF118C"
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6InN4OEFudTd0MzY0MDZYZGlibHFRSmdEUEVZdyIsIng1dCI6InN4OEFudTd0MzY0MDZYZGlibHFRSmdEUEVZdyJ9.eyJzdWIiOiJtZUBjb21wYW55LmNvbSIsImp0aSI6Ijk4NWQyNGNDOTZDMjQxMTA5N0E3NjAzMGY1OTM4RGQzIiwiaWF0IjoxNTkyNTgwOTA1LCJuYmYiOjE1OTI1ODA5MDUsImV4cCI6MTU5MjU4MTIwNX0.whJap3yJIYLIZ4BrK4tVHQVARGstI_omkoo2odOaSpTXZRh104Kyv7J3kiRPaNWKM7t_rpEVylmX-rzY_k_-d7auysVgQL2d-xNa8ZJGmjEemniPy2qRjbpdKDONlija7sbt_7E2n6_0kiwOiu31NemVr1EoWnpGLQeSfgjExuQPHatoKmi5UfijG0P4pWeo3xYyukYE14XOVGYI0ym3yl7gh7YUq9YkKZHvnMulzUoXWImZQ3_0ihC4CwD7QfqKbBuYGCAFtfJ55WHc_iX9EjgVS69aPLIciQmRtvr-xkVG4QApKTLb5NS5dJHKwVxvDojb2OBH5bQM5PMGxpRcIA"
        Test-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -VerificationCertificate $cert

        Verifies a digital signature for an RSA signed JSON Web Token against a certificate with thumbprint B31F009EEEEDDFAE34E977626E5A902600CF118C.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
        $jwk = '
        {
            "kty": "RSA",
            "use": "sig",
            "e": "AQAB",
            "n": "0yvTvlqT5yrk6lDzmK5_i6e-NKW4Bw8J9U62rcWI4IAr-vKaNqitmSwVLr2jJu29xQ__W22iGu584A82AS5N5YrwA6Rek-7WuHinwupFtCN-cCTzJlAcXUxyU7H0LfFxsXS1LUxSl7F_liIKH81QFE5RvI97R9bmbCn_BXpK4pHnTBGJigA8gJQ0U__YFk7AOSFUBeursQfCVPID99FpQ6pyj-h9WgdOneAfWde4SM1Pnovw59T2UT-JO-ObA5WOtvl0xW21djhhBRusVGWJuncNElhhRpUqNSOcsNQVe026zw8dX1wiMs9migQmz_LokH1bHENIuybdK9xBhXRRbw",
            "kid": "2yCvZnk7k8W66wR2LXR9WCswhAc"
        }
        '
        Test-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -JsonWebKey $jwk

        Verifies a JSON Web Token's digital signature against a JSON Web Key.
    .OUTPUTS
        System.Boolean
    .LINK
        https://tools.ietf.org/html/rfc7515
        https://tools.ietf.org/html/rfc7517
		https://tools.ietf.org/html/rfc7519
        New-JwtSignature
        New-JsonWebKeySet
#>

    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [ValidateLength(16, 8192)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory = $true, Position = 1)][ValidateSet("SHA256", "SHA384", "SHA512")][String]$HashAlgorithm,

        [Parameter(Mandatory = $true, ParameterSetName = "RSA", Position = 2)][Alias("Certificate", "Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$VerificationCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = "HMAC", Position = 2)]
        [ValidateLength(1, 32768)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "HMACSecure", Position = 2)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$SecureKey,

        [Parameter(Mandatory = $true, ParameterSetName = "JWK", Position = 2)][Alias("jwk")][ValidateLength(12, 1073741791)][String]$JsonWebKey
    )

    BEGIN {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS {
        [bool]$signatureVerifies = $false

        [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken -VerifySignaturePresent

        if (-not($isValidJwt)) {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }


        if ($PSCmdlet.ParameterSetName -eq "RSA") {
            if ($null -ne $VerificationCertificate.PrivateKey.KeyExchangeAlgorithm) {
                Write-Warning -Message "It is not necessary to perform signature verification with a certificate that has private key!"
            }

            try {
                $signatureVerifies = Test-JwtRsaSignature -JsonWebToken $JsonWebToken -VerificationCertificate $VerificationCertificate -HashAlgorithm $HashAlgorithm -ErrorAction Stop
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq "JWK") {
            try {
                $signatureVerifies = Test-JwtJwkSignature -JsonWebToken $JsonWebToken -JsonWebKey $JsonWebKey -HashAlgorithm SHA256 -ErrorAction Stop
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }

        }
        else {
            # Parameter set is HMAC or HMACSecure
            [string]$hmacKey = ""
            if ($PSCmdlet.ParameterSetName -eq "HMACSecure") {
                $networkCredential = [System.Net.NetworkCredential]::new("", $SecureKey)
                $hmacKey = $networkCredential.Password
            }
            else {
                $hmacKey = $Key
            }

            $jwtHeader = Get-JsonWebTokenHeader -JsonWebToken $JsonWebToken -AsEncodedString
            $jwtPayload = Get-JsonWebTokenPayload -JsonWebToken $JsonWebToken -AsEncodedString
            $jwtSig = Get-JsonWebTokenSignature -JsonWebToken $JsonWebToken -AsEncodedString

            $jwtNoSig = "{0}.{1}" -f $jwtHeader, $jwtPayload

            [string]$hmacSig = ""
            try {
                $hmacSig = New-JwtSignature -JsonWebToken $jwtNoSig -Key $hmacKey -HashAlgorithm $HashAlgorithm -ErrorAction Stop
            }
            catch {
                $signatureExceptionMessage = "Unable to generate signature for given header and payload."
                $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $signatureExceptionMessage
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }

            if ($hmacSig -eq $jwtSig) {
                $signatureVerifies = $true
            }
        }

        return $signatureVerifies
    }
}

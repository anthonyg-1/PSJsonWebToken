function Test-JsonWebToken {
    <#
    .SYNOPSIS
        Validates a JSON Web Token.
    .DESCRIPTION
        Validates a JSON Web Token signature and date range. If the SkipExpirationCheck parameter is used then only the token signature is validated.
    .PARAMETER JsonWebToken
        The JSON Web Token that is to validated.
    .PARAMETER HashAlgorithm
        The hash algorithim for the signature. Acceptable values are SHA256, SHA384, and SHA512. Default value is SHA256.
    .PARAMETER VerificationCertificate
        The certificate containing the public key that will be used to verify the signature of the JSON Web Token.
    .PARAMETER Key
        The secret key used to validate an HMAC signature expressed as a string.
    .PARAMETER SecureKey
        The secret key used to validate an HMAC signature expressed as a System.Security.SecureString.
    .PARAMETER JsonWebKey
        The JSON Web Key (X509 certificate public key) to verify the signature of the JSON Web Token per RFC 7517.
    .PARAMETER Uri
        Specifies the Uniform Resource Identifier (URI) containing the JSON Web Keys to validate the JSON Web Token against. Can be a well-known OpenID Connect discovery endpoint or a link containing the JWKs directly.
    .PARAMETER Audience
        The intended recipient of the JSON Web Token.
    .PARAMETER Issuer
        The principal that issued the JSON Web Token.
    .PARAMETER SkipExpirationCheck
        Tells this function to verify the signature of the JWT only and not to evaluate token expiration.
    .EXAMPLE
        $signingCertThumbprint = "6C85DF2F915D0E28B719AEC188367092A0FD0CD2"
        $certPath = Join-Path -Path Cert:\LocalMachine\My -ChildPath $signingCertThumbprint
        $cert = Get-Item -Path $certPath

        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCNTMjU2IjoiYklYZkw1RmREaWkzR2E3QmlEWndrcUQ5RE5JIn0.eyJHaXZlbk5hbWUiOiJUb255IiwiTmFtZUlkIjoidG9ueS5ndWltZWxsaUBmbWdsb2JhbC5jb20iLCJTdXJuYW1lIjoiR3VpbWVsbGkiLCJqdGkiOiIyOUM1NTkwMWRiZDE0NmJDYjA3MjM5MDg5ZDJmQzJGRCIsImlhdCI6MTQ2NzgyODg1NywibmJmIjoxNDY3ODI4ODU3LCJleHAiOjE0Njc4MjkxNTd9.DgdcHarlI6gi6A4uX3kfQEfXRtD4fORp1svlIE8M_Ynr4cGjfncMyNkhPSplREX2509-pjbf90BpDqCoveGuvXKnWYFnGkfH8Cad-1qmurPQMyx_LTBW0jaw9lI7mVRFyN-I2lC0bw4QjC7QWrWctUE_v-OMSQIrAoNbaAKTVWjAcFC2reQymLL0zvLJ9MJ0RV4kQWBqMBaye7BuEnRfiEicJ57lg7cGCge2jYNYFNL2lBrOblr0SS4p8SUzQ-5WXj3gMT9K75_ai3Mg4UCHTZ9DAIDP29jHRdX7YTACVagQDZDPuZB1coJiemaSEJGvrDtfLOuR-MnGkRwCa88wfw"

        Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -VerificationCertificate $cert

        Validates a JSON Web Token's structure and verifies the signature against the certificate found in the local machine store with a thumbprint of 6C85DF2F915D0E28B719AEC188367092A0FD0CD2.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDU5ODU5NjUsIm5iZiI6MTYwNTk4NTk2NSwiZXhwIjoxNjA1OTg2MjY1LCJzdWIiOiJ0b255In0.8ReUtDR9hiFtvvZtbtAvD1s3IYmt7uhXdLQyXY1Q4UM"
        Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -Key "secretkey" -SkipExpirationCheck

    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDU5ODY1ODgsIm5iZiI6MTYwNTk4NjU4OCwiZXhwIjoxNjA1OTg2ODg4LCJzdWIiOiJ0b255In0.L2-gWEAJvkb5UtPav_v8zqWplJkUVULX_-QOE3jVbqY"
        $secureStringKey = "secretKey" | ConvertTo-SecureString -AsPlainText -Force
        Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -SecureKey $secureStringKey -SkipExpirationCheck

        Validates an HMAC-SHA256 signature only (not date range check) against a JWT with the HMAC key passed as a SecureString.
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
        Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -JsonWebKey $jwk

        Verifies a JSON Web Token's digital signature against a JSON Web Key as well as determining that that token is not expired.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
        $jwkUri = "https://app.mycompany.com/common/discovery/keys.json"
        Test-JsonWebToken -JsonWebToken $jwt -Uri $jwkUri -HashAlgorithm SHA256 -SkipExpirationCheck -Verbose

        Attempts to validate a JSON Web Token signature against a collection of JSON Web Keys in https://app.mycompany.com/common/discovery/keys.json and provides verbose output detailing what JWK was used to verify the signature.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzIyNjk0MDcsIm5iZiI6MTY3MjI2OTQwNywiZXhwIjoxNjcyMjY5NzA3LCJpc3MiOiJteWlkcCIsInN1YiI6InRvbnkiLCJhdWQiOiJteWFwcCJ9.6pgmpyVCo9mzCgL07lhAHg5EUbAqYqS6YcxunrlfEYQ"
        Test-JsonWebToken -JsonWebToken $jwt -Key "secret" -Audience "myapp" -Issuer "myidp" -SkipExpirationCheck -Verbose

        Validates an HMAC-SHA256 signed JWT signature as well as audience and issuer claims (no expiration check) displaying verbose output.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzIyNjk0MDcsIm5iZiI6MTY3MjI2OTQwNywiZXhwIjoxNjcyMjY5NzA3LCJpc3MiOiJteWlkcCIsInN1YiI6InRvbnkiLCJhdWQiOiJteWFwcCJ9.6pgmpyVCo9mzCgL07lhAHg5EUbAqYqS6YcxunrlfEYQ"
        Test-JsonWebToken -JsonWebToken $jwt -Key "secret" -Audience "myapp" -Verbose

        Attempts to validate an HMAC-SHA256 signed JWT including the signature, audience, and expiration.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzIyNjk0MDcsIm5iZiI6MTY3MjI2OTQwNywiZXhwIjoxNjcyMjY5NzA3LCJpc3MiOiJteWlkcCIsInN1YiI6InRvbnkiLCJhdWQiOiJteWFwcCJ9.6pgmpyVCo9mzCgL07lhAHg5EUbAqYqS6YcxunrlfEYQ"
        Test-JsonWebToken -JsonWebToken $jwt -Key "secret" -Issuer "myidp" -SkipExpirationCheck -Verbose

        Attempts to validate an HMAC-SHA256 signed JWT including the signature and issuer excluding expiration.
    .OUTPUTS
       System.Boolean
    .LINK
        https://tools.ietf.org/html/rfc7519
        https://tools.ietf.org/html/rfc7515
        https://tools.ietf.org/html/rfc7517
        New-JsonWebToken
#>
    [CmdletBinding()]
    [Alias('tjwt', 'ValidateJwt')]
    [OutputType([System.Boolean])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [ValidateLength(16, 131072)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet("SHA256", "SHA384", "SHA512")]
        [String]$HashAlgorithm = "SHA256",

        [Parameter(Mandatory = $true, ParameterSetName = "RSA", Position = 3)][Alias("Certificate", "Cert")]
        [ValidateNotNullOrEmpty()][System.Security.Cryptography.X509Certificates.X509Certificate2]$VerificationCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = "HMAC", Position = 3)]
        [ValidateLength(1, 32768)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "HMACSecure", Position = 3)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$SecureKey,

        [Parameter(Mandatory = $true, ParameterSetName = "JWK", Position = 3)][Alias("jwk")][ValidateLength(12, 1073741791)][String]$JsonWebKey,

        [Parameter(Mandatory = $true, ParameterSetName = "URI", Position = 3)][Alias('OidcUri', 'JwkUri')][System.Uri]$Uri,

        [Parameter(Mandatory = $false, Position = 4)][ValidateLength(2, 131072)][Alias("aud")][String]$Audience,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateLength(2, 131072)][Alias("iss")][String]$Issuer,

        [Parameter(Mandatory = $false, Position = 6)]
        [Switch]$SkipExpirationCheck
    )
    BEGIN {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS {
        [bool]$jwtIsValid = $false
        [bool]$signatureIsValid = $false
        [bool]$tokenIsNotExpired = $false
        [bool]$audienceIsValid = $false
        [bool]$issuerIsValid = $false

        [bool]$hasValidJwtStructure = Test-JwtStructure -JsonWebToken $JsonWebToken -VerifySignaturePresent
        if (-not($hasValidJwtStructure)) {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        [string]$missingDateExceptionMessage = "Unable to validate token lifetime due to missing exp claim in payload. If signature validation only is required use the SkipExpirationCheck parameter."

        # Verbose messages:
        [string]$sigValidMessage = "Signature was verified."
        [string]$sigInvalidMessage = "Signature was not verified."
        [string]$dateRangedValidMessage = "JWT date range is valid."
        [string]$dateRangedNotValidMessage = "JWT is expired."

        $payload = $null
        if ($PSBoundParameters.ContainsKey("Audience") -or $PSBoundParameters.ContainsKey("Issuer")) {
            $payload = Get-JsonWebTokenPayload -JsonWebToken $JsonWebToken
        }

        $headerTable = Get-JsonWebTokenHeader -JsonWebToken $JsonWebToken
        [bool]$jwtHeaderContainsKid = $false
        if ($headerTable.ContainsKey("kid")) {
            $jwtHeaderContainsKid = $true
            $headerKid = $headerTable["kid"]
            $kidMessage = "Identifier of the signing key for the JWT: {0}" -f $headerKid
            Write-Verbose -Message $kidMessage
        }

        if ($PSCmdlet.ParameterSetName -eq "RSA") {
            try {
                $signatureIsValid = Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -VerificationCertificate $VerificationCertificate -ErrorAction Stop
            }
            catch {
                Write-Error -Exception $_ -Category InvalidResult -ErrorAction Stop
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq "JWK") {
            if ($jwtHeaderContainsKid) {
                $deserializedJwk = $null
                try {
                    $deserializedJwk = $JsonWebKey | ConvertFrom-Json -ErrorAction Stop

                    [bool]$kidMatches = $headerKid -eq $deserializedJwk.kid

                    if ($kidMatches) {
                        if (Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -JsonWebKey $JsonWebKey -ErrorAction Stop) {
                            $signatureIsValid = $true
                            $sigVerifiedAgainstJwkMessage = "Verified signature against the following JWK: {0}" -f $JsonWebKey
                            Write-Verbose -Message $sigVerifiedAgainstJwkMessage
                        }
                        else {
                            $jwkInvalidMessage = "Unable to verify signature against the following JWK: {0}" -f $JsonWebKey
                            Write-Verbose -Message $jwkInvalidMessage
                        }
                    }
                    else {
                        $kidInvalidMessage = "Passed JWK does not contain the following signing key identifier: {0}" -f $headerKid
                        Write-Verbose -Message $kidInvalidMessage
                    }
                }
                catch {
                    Write-Error -Exception $_.Exception -ErrorAction Stop
                }
            }
            else {
                try {
                    if (Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -JsonWebKey $JsonWebKey -ErrorAction Stop) {
                        $signatureIsValid = $true
                        $sigVerifiedAgainstJwkMessage = "Verified signature against the following JWK: {0}" -f $JsonWebKey
                        Write-Verbose -Message $sigVerifiedAgainstJwkMessage
                    }
                    else {
                        $jwkInvalidMessage = "Unable to verify signature against the following JWK: {0}" -f $JsonWebKey
                        Write-Verbose -Message $jwkInvalidMessage
                    }
                }
                catch {
                    Write-Error -Exception $_.Exception -Category InvalidResult -ErrorAction Stop
                }
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq "URI") {
            $jsonWebKeys = @()
            try {
                $jsonWebKeys += (Get-JwkCollection -Uri $Uri -AsJson -ErrorAction Stop)
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }

            $discoveredJwk = $jsonWebKeys | ConvertFrom-Json -ErrorAction Stop | Where-Object -Property kid -eq $headerKid
            [bool]$kidMatches = $null -ne $discoveredJwk

            if ($jwtHeaderContainsKid) {
                try {
                    if ($kidMatches) {
                        $kidMatchesMessage = "JWT header contains key identifier that corresponds with the following key identifier in the JWK set: {0}. Attempting signature verification now." -f $headerKid
                        Write-Verbose -Message $kidMatchesMessage
                        [string]$targetJwk = $discoveredJwk | ConvertTo-Json -Depth 25 -Compress -ErrorAction Stop
                        if (Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -JsonWebKey $targetJwk -ErrorAction Stop) {
                            $signatureIsValid = $true
                            $sigVerifiedAgainstJwkMessage = "Verified signature against the following JWK: {0}" -f $targetJwk
                            Write-Verbose -Message $sigVerifiedAgainstJwkMessage
                        }
                        else {
                            $jwkInvalidMessage = "Unable to verify signature against the following JWK: {0}" -f $targetJwk
                            Write-Verbose -Message $jwkInvalidMessage
                        }
                    }
                    else {
                        $kidInvalidMessage = "Unable to find a JWK with the following signing key identifier: {0}" -f $headerKid
                        Write-Verbose -Message $kidInvalidMessage
                    }
                }
                catch {
                    Write-Error -Exception $_.Exception -Category InvalidResult -ErrorAction Stop
                }
            }
            else {
                $kidNotFoundMessage = "Signing key identifier (kid attribute) not found in JWT header. Iterating through collection of JWKs."
                Write-Verbose -Message $kidNotFoundMessage

                foreach ($jwk in $jsonWebKeys) {
                    try {
                        if (Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -JsonWebKey $jwk -ErrorAction Stop) {
                            $signatureIsValid = $true
                            $sigVerifiedAgainstJwkMessage = "Verified signature against the following JWK: {0}" -f $jwk
                            Write-Verbose -Message $sigVerifiedAgainstJwkMessage
                            break
                        }
                        else {
                            $jwkInvalidMessage = "Unable to verify signature against the following JWK: {0}" -f $jwk
                            Write-Verbose -Message $jwkInvalidMessage
                        }
                    }
                    catch {
                        Write-Error -Exception $_.Exception -Category InvalidResult -ErrorAction Stop
                    }
                }
            }
        }
        else {
            # Parameter set is HMAC or HMACSecure
            if ($PSCmdlet.ParameterSetName -eq "HMACSecure") {
                try {
                    $signatureIsValid = Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -SecureKey $SecureKey -ErrorAction Stop
                }
                catch {
                    Write-Error -Exception $_ -Category InvalidResult -ErrorAction Stop
                }
            }
            else {
                try {
                    $signatureIsValid = Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -Key $Key -ErrorAction Stop
                }
                catch {
                    Write-Error -Exception $_ -Category InvalidResult -ErrorAction Stop
                }
            }
        }

        if ($signatureIsValid) {
            Write-Verbose -Message $sigValidMessage
        }
        else {
            Write-Verbose -Message $sigInvalidMessage
        }

        if ($PSBoundParameters.ContainsKey("SkipExpirationCheck")) {
            $jwtIsValid = $signatureIsValid
        }
        else {
            [bool]$tokenIsNotExpired = $false
            try {
                $tokenIsNotExpired = Test-JwtDateRange -JsonWebToken $JsonWebToken -ErrorAction Stop
            }
            catch {
                $ArgumentException = New-Object -TypeName System.ArgumentException -Argument $missingDateExceptionMessage
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }

            if ($tokenIsNotExpired) {
                Write-Verbose -Message $dateRangedValidMessage
            }
            else {
                Write-Verbose -Message $dateRangedNotValidMessage
            }

            $jwtIsValid = $signatureIsValid -and $tokenIsNotExpired
        }

        if ($PSBoundParameters.ContainsKey("Audience")) {
            if ($payload.ContainsKey("aud")) {
                if ($Audience -cin $payload["aud"]) {
                    $audienceIsValid = $true
                }

                if ($audienceIsValid) {
                    Write-Verbose -Message "Token audience validated."
                }
                else {
                    Write-Verbose -Message ("JWT payload does not contain the audience: {0}" -f $Audience)
                }
            }
            else {
                Write-Verbose "JWT payload does not contain an audience claim."
            }

            $jwtIsValid = $jwtIsValid -and $audienceIsValid
        }

        if ($PSBoundParameters.ContainsKey("Issuer")) {
            if ($payload.ContainsKey("iss")) {
                if ($payload["iss"] -eq $Issuer) {
                    $issuerIsValid = $true
                }

                if ($issuerIsValid) {
                    Write-Verbose -Message "Token issuer validated."
                }
                else {
                    Write-Verbose -Message ("JWT payload does not contain the issuer: {0}" -f $Issuer)
                }
            }
            else {
                Write-Verbose "JWT payload does not contain an issuer claim."
            }

            $jwtIsValid = $jwtIsValid -and $issuerIsValid
        }

        return $jwtIsValid
    }
}

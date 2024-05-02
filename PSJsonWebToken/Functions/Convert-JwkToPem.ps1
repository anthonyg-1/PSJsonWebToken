function Convert-JwkToPem {
    <#
    .SYNOPSIS
        Converts a JWK public key to a PEM.
    .DESCRIPTION
        Converts JWKs (JSON Web Keys) to formatted PEM (Privacy Enhanced Mail) outputs as well as converting JWKs to unformatted Base64 encoded public keys.
    .PARAMETER Uri
        Specifies the Uniform Resource Identifier (URI) for the JWK set containing the JWKS to convert to PEM format.
    .PARAMETER JsonWebKey
        Specifies an individual JWK string to convert to PEM format.
    .EXAMPLE
        $jwkUri = "https://app.mycompany.com/common/discovery/keys.json"
        Convert-JwkToPem -Uri $jwkUri

        Converts the JWKs in the JWK set found in https://app.mycompany.com/common/discovery/keys.json to PEM format.
    .EXAMPLE
        $myJwk = '{
            "kty": "RSA",
            "use": "sig",
            "e": "AQAB",
            "n": "9te1S7Yps5jx1TZtVOo3R_jy157SO-XknHU4WJ5PJ9WdCUXj06PL4HqEgCrXuYLtO8Rl78S1KXD6NRed57fMxB3IhHGEZFuJ_lM6V6l9Y3RqSnOhs0cG_1NohjGeIPbk4u4j4PQDBsbe87qeerBeCsV5hmsQDTC11j_knkkl0cGvhHIcfDkoNS0KyY0LEqCLKaBKxJ7y7oVub5ZR1yHGOzTgFqHY2FcZ9d8wQhc65ngnXQUuI1BplFdEsRAUez5f1_ru3sTQQK7RikH_v2WGltBTQRnfJ4cP3d8SMfcAnKr8QVYdnIFTPocD-k3tkhJjhDpFig8CnN9xca_LWrFhHQ",
            "kid": "jSVgE1Q4he8hiX199BTlS-9YJQE"
        }
        '
        Convert-JwkToPem -JsonWebKey $myJwk | Select -Expand Pem | Out-File .\key.pem -Encoding ascii

        Converts the passed JWK into a PEM string and saves it to a file.
    .OUTPUTS
        PSJsonWebToken.PemFromJwkResult

            An object containing the JWK ID, PEM and unformatted Base64 public key.    .
    .LINK
		https://tools.ietf.org/html/rfc7517
        https://www.rfc-editor.org/rfc/rfc7468
        Select-Object
        Out-File
        New-JsonWebKey
        New-JsonWebKeySet
    #>
    [CmdletBinding()]
    [Alias('cjwk')]
    [OutputType([PSJsonWebToken.PemFromJwkResult])]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = "URI", Position = 0)][Alias('OidcUri', 'JwkUri')][System.Uri]$Uri,
        [Parameter(Mandatory = $true, ParameterSetName = "JWK", Position = 1)][Alias("jwk")][ValidateLength(12, 1073741791)][String]$JsonWebKey
    )
    BEGIN {
        function _TransformJwkToPem([string]$jwk) {
            try {
                $jwkObject = $jwk | ConvertFrom-Json -ErrorAction Stop

                if (($null -eq $jwkObject.kty) -or ($jwkObject.kty -ne "RSA") -or ($null -eq $jwkObject.n) -or ($null -eq $jwkObject.e)) {
                    $ArgumentException = 'JSON Web Key schema validation failed. Ensure that a valid JWK is passed that contains the key type expressed as "kty", a public exponent as "e”, and modulus as "n" parameters per RFC 7517.'
                    Write-Error -Exception $ArgumentException -ErrorAction Stop
                }

                $rsaParams = [RSAParameters]::new()

                $rsaParams.Exponent = $jwkObject.e | ConvertFrom-Base64UrlEncodedString -AsBytes -ErrorAction Stop
                $rsaParams.Modulus = $jwkObject.n | ConvertFrom-Base64UrlEncodedString -AsBytes -ErrorAction Stop

                $rsaCryptoSp = [RSACryptoServiceProvider]::new()
                $rsaCryptoSp.ImportParameters($rsaParams)

                [byte[]]$publicKeyBytes = $rsaCryptoSp.ExportSubjectPublicKeyInfo()
                [string]$publicKeyUnformatted = ConvertTo-Base64UrlEncodedString -Bytes $publicKeyBytes -ErrorAction Stop
                [string]$publicKeyPem = $rsaCryptoSp.ExportSubjectPublicKeyInfoPem()

                $rsaCryptoSp.Dispose()

                $result = [PSJsonWebToken.PemFromJwkResult]::new()
                $result.JwkIdentifier = $jwkObject.kid
                $result.Pem = $publicKeyPem
                $result.PublicKeyUnformatted = $publicKeyUnformatted

                return $result
            }
            catch {
                $SerializationException = [SerializationException]::new('JSON Web Key schema validation failed. Ensure that a valid JWK is passed that contains the key type expressed as "kty", a public exponent as "e”, and modulus as "n" parameters per RFC 7517.')
                Write-Error -Exception $SerializationException -Category InvalidData -ErrorAction Stop
            }
        }
    }
    PROCESS {
        if ($PsCmdlet.ParameterSetName -eq "URI") {

            $jsonWebKeys = @()
            try {
                $jsonWebKeys += (Get-JwkCollection -Uri $Uri -AsJson -ErrorAction Stop)
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }

            foreach ($jwk in $jsonWebKeys) {
                try {
                    $resultingPemObject = _TransformJwkToPem -jwk $jwk
                    Write-Output -InputObject $resultingPemObject
                }
                catch {
                    Write-Error -Exception $_.Exception -ErrorAction Stop
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq "JWK") {
            try {
                $resultingPemObject = _TransformJwkToPem -jwk $JsonWebKey
                Write-Output -InputObject $resultingPemObject
            }
            catch {
                Write-Error -Exception $_.Exception -ErrorAction Stop
            }
        }
    }
}

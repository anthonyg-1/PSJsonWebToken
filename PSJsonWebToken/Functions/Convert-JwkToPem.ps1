function Convert-JwkToPem {
    <#
    .SYNOPSIS
        Converts a JWK public key to a PEM.
    .DESCRIPTION
        Converts a JWK (JSON Web Key) to formatted PEM (Privacy Enhanced Mail) as well as an unformatted Base64 encoded public key.
    .PARAMETER Uri
        Specifies the Uniform Resource Identifier (URI) containing the JSON Web Keys to convert to PEM format.
    .EXAMPLE
        $jwkUri = "https://app.mycompany.com/common/discovery/keys.json"
        Convert-JwkToPem -Uri $jwkUri

        Converts the JWKs in the JWK set found in https://app.mycompany.com/common/discovery/keys.json to PEM format.
    .OUTPUTS
        PSJsonWebToken.PemFromJwkResult

            An object containing the JWK ID, PEM and unformatted Base64 public key.    .
    .LINK
		https://tools.ietf.org/html/rfc7517
        https://www.rfc-editor.org/rfc/rfc7468
    #>
    [CmdletBinding()]
    [Alias('cjwk')]
    [OutputType([PSJsonWebToken.PemFromJwkResult])]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = "URI", Position = 1)][Alias('OidcUri', 'JwkUri')][System.Uri]$Uri
    )
    PROCESS {
        $jsonWebKeys = @()
        try {
            $jsonWebKeys += (Get-JwkCollection -Uri $Uri -ErrorAction Stop)
        }
        catch {
            Write-Error -Exception $_.Exception -ErrorAction Stop
        }

        $SerializationException = [SerializationException]::new("Unable to deserialize JSON Web Key.")

        foreach ($jwk in $jsonWebKeys) {
            try {
                $rsaParams = [RSAParameters]::new()

                $rsaParams.Exponent = $jwk.e | ConvertFrom-Base64UrlEncodedString -AsBytes -ErrorAction Stop
                $rsaParams.Modulus = $jwk.n | ConvertFrom-Base64UrlEncodedString -AsBytes -ErrorAction Stop

                $rsaCryptoSp = [RSACryptoServiceProvider]::new()
                $rsaCryptoSp.ImportParameters($rsaParams)

                [byte[]]$publicKeyBytes = $rsaCryptoSp.ExportSubjectPublicKeyInfo()
                [string]$publicKeyUnformatted = ConvertTo-Base64UrlEncodedString -Bytes $publicKeyBytes -ErrorAction Stop
                [string]$publicKeyPem = $rsaCryptoSp.ExportSubjectPublicKeyInfoPem()

                $rsaCryptoSp.Dispose()

                $result = [PSJsonWebToken.PemFromJwkResult]::new()
                $result.JwkIdentifier = $jwk.kid
                $result.Pem = $publicKeyPem
                $result.UnformattedCertificate = $publicKeyUnformatted

                Write-Output -InputObject $result
            }
            catch {
                Write-Error -Exception $SerializationException -Category InvalidData -ErrorAction Stop
            }
        }
    }
}

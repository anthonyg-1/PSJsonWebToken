function New-JsonWebKeySet {
    <#
    .SYNOPSIS
        Generates a JSON Web Key set containing a single key.
    .DESCRIPTION
        Transforms an X509Certificate2 object into a JSON object known as a JSON Web Key (JWK) and adds it to a JWK set.
    .PARAMETER Certificate
        The certificate that will be converted into a JSON Web Key.
    .PARAMETER KeyOperations
        The public key operation that this JWK will be used for. Verification is the default.
    .PARAMETER IncludeChain
        Tells the function to include the full certificate chain which includes not only the end-entity certificate, but also the issuing and root certificate in the x5c property (X.509 Certificate Chain). Not selecting this parameter will result in x5c property containing the end-entity certificate only.
    .PARAMETER Compress
        Omits white space and indented formatting in the output JSON Web Key set.
    .EXAMPLE
        $certThumbprint = "706428667193645C3B4704FC824BEDFCEBB4F038"
        $certPath = Join-Path -Path Cert:\LocalMachine\My -ChildPath $certThumbprint
        $verificationCert = Get-Item -Path $certPath

        $verificationCert | New-JsonWebKeySet -KeyOperations Verification

        Generates a JSON Web Key set for purposes of signature verification from certificate with thumbprint 706428667193645C3B4704FC824BEDFCEBB4F038.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2

            A X509Certificate2 object is received by the Certificate parameter.
    .OUTPUTS
        System.String
    .NOTES
        Unlike New-JsonWebKey, which returns objects by default, New-JsonWebKeySet returns a serialized result only.
    .LINK
		https://tools.ietf.org/html/rfc7517
		New-JsonWebToken
        New-JsonWebKey
#>
    [CmdletBinding()]
    [Alias('njwks', 'CreateJwkSet')]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Verification", "Encryption")]
        [System.String]$KeyOperations = "Verification",

        [Parameter(Mandatory = $false, Position = 2)][Switch]$IncludeChain,

        [Parameter(Mandatory = $false, Position = 3)][Switch]$Compress
    )

    PROCESS {
        [string]$jwkSet = ""

        $encodedThumbprint = ConvertTo-Base64UrlEncodedString -Bytes ($Certificate.GetCertHash())

        [string]$publicKeyUse = ""
        switch ($KeyOperations) {
            "Verification" { $publicKeyUse = "sig" }
            "Encryption" { $publicKeyUse = "enc" }
            default { $publicKeyUse = "sig" }
        }

        $X509CertificateChain = [List[String]]::new()
        if ($PSBoundParameters.ContainsKey("IncludeChain")) {
            [X509Chain]$certChain = [X509Chain]::new()
            $certChain.Build($Certificate) | Out-Null

            foreach ($chainElement in $certChain.ChainElements) {
                $rawData = $chainElement.Certificate.RawData
                $base64 = [Convert]::ToBase64String($rawData)
                $X509CertificateChain.Add($base64)
            }
        }
        else {
            $rawData = $Certificate.RawData
            $base64 = [Convert]::ToBase64String($rawData)
            $X509CertificateChain.Add($base64)
        }

        $key = $Certificate.PublicKey.Key

        if ($null -ne $key) {
            [RSAParameters]$parameters = $key.ExportParameters($false)
            [byte[]]$exp = $parameters.Exponent
            [byte[]]$mod = $parameters.Modulus

            [string]$encodedExponent = ConvertTo-Base64UrlEncodedString -Bytes $exp
            [string]$encodedModulus = ConvertTo-Base64UrlEncodedString -Bytes $mod
        }

        $jwkTable = [ordered]@{kty = "RSA"
            use                    = $publicKeyUse
            e                      = $encodedExponent
            n                      = $encodedModulus
            kid                    = $encodedThumbprint
            x5t                    = $encodedThumbprint
            x5c                    = $X509CertificateChain
        }

        $jwkSetTable = [ordered]@{keys = $jwkTable}

        if ($PSBoundParameters.ContainsKey("Compress")) {
            $jwkSet = $jwkSetTable | ConvertTo-Json -Compress
        }
        else {
            $jwkSet = $jwkSetTable | ConvertTo-Json
        }

        return $jwkSet
    }
}

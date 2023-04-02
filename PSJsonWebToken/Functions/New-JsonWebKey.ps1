function New-JsonWebKey {
    <#
    .SYNOPSIS
        Generates a JSON Web Key from an x509 certificate.
    .DESCRIPTION
        Transforms an X509Certificate2 object into a JSON object known as a JSON Web Key (JWK).
    .PARAMETER Certificate
        The certificate that will be converted into a JSON Web Key.
    .PARAMETER KeyOperations
        The public key operation that this JWK will be used for. Verification is the default.
    .PARAMETER IncludeCertificate
        Tells the function to include the base 64 encoded x509 certificate expressed as the x5c property. This parameter returns the end-entity certificate only.
    .PARAMETER IncludeCertificateChain
        Tells the function to include the full certificate chain which includes not only the end-entity certificate, but also the issuing and root certificate in the x5c property (X.509 Certificate Chain).
    .PARAMETER AsJson
         Tells the function to return JSON as opposed to an object.
    .PARAMETER Compress
        Omits white space and indented formatting in the output JSON Web Key.
    .EXAMPLE
        $certThumbprint = "706428667193645C3B4704FC824BEDFCEBB4F038"
        $certPath = Join-Path -Path Cert:\LocalMachine\My -ChildPath $certThumbprint
        $verificationCert = Get-Item -Path $certPath

        $verificationCert | New-JsonWebKey -KeyOperations Verification

        Generates a JSON Web Key for purposes of signature verification from certificate with thumbprint 706428667193645C3B4704FC824BEDFCEBB4F038.
    .EXAMPLE
        $certificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where Subject -Like "*jwt*"
        $jwks = @()
        foreach ($cert in $certificates)
        {
            $jwks+= $cert | New-JsonWebKey
        }
        $jwksSet = @{keys=$jwks} | ConvertTo-Json

        Obtains a collection of certificates from Cert:\LocalMachine\My where the subject contains the string "jwt", and for each one of them converts them to a JWK object, adds them to an array and serializes the result into a JWK set.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2

            A X509Certificate2 object is received by the Certificate parameter.
    .OUTPUTS
        System.Management.Automation.PSCustomObject or System.String
     .NOTES
        Unlike New-JsonWebKeySet, which only returns the JWK set serialized, New-JsonWebKey returns an object by default with the option to serialize via the AsJson parameter.
    .LINK
		https://tools.ietf.org/html/rfc7517
		New-JsonWebToken
        New-JsonWebKeySet
        Get-ChildItem
        ConvertTo-Json
        https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-7.1
#>
    [CmdletBinding()]
    [Alias('njwk', 'CreateJwk')]
    [OutputType([System.Management.Automation.PSCustomObject], [System.String])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Verification", "Encryption")]
        [System.String]$KeyOperations = "Verification",

        [Parameter(Mandatory = $false, Position = 2)][Alias('IncludeCert', 'ic')][Switch]$IncludeCertificate,
        [Parameter(Mandatory = $false, Position = 3)][Alias('IncludeChain', 'icc')][Switch]$IncludeCertificateChain,

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = "JSON")][Switch]$AsJson,
        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = "JSON")][Switch]$Compress
    )

    PROCESS {
        [PSCustomObject]$jwkObject = $null

        $encodedThumbprint = Get-JwtKeyIdentifier -Certificate $Certificate

        [string]$publicKeyUse = ""
        switch ($KeyOperations) {
            "Verification" { $publicKeyUse = "sig" }
            "Encryption" { $publicKeyUse = "enc" }
            default { $publicKeyUse = "sig" }
        }

        [bool]$certShouldBeReturned = ($PSBoundParameters.ContainsKey("IncludeCertificateChain")) -or ($PSBoundParameters.ContainsKey("IncludeCertificate"))

        $X509CertificateChain = [List[String]]::new()
        if ($certShouldBeReturned) {
            if ($PSBoundParameters.ContainsKey("IncludeCertificateChain")) {
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
        }
        else {
            $X509CertificateChain = $null
        }

        $key = $Certificate.PublicKey.Key

        if ($null -ne $key) {
            [RSAParameters]$parameters = $key.ExportParameters($false)
            [byte[]]$exp = $parameters.Exponent
            [byte[]]$mod = $parameters.Modulus

            [string]$encodedExponent = ConvertTo-Base64UrlEncodedString -Bytes $exp
            [string]$encodedModulus = ConvertTo-Base64UrlEncodedString -Bytes $mod
        }
        else {
            $noKeyExceptionMessage = "Unable to obtain public key from supplied certificate."
            $CryptographicException = [CryptographicException]::new($noKeyExceptionMessage)
            Write-Error -Exception $CryptographicException -Category SecurityError -ErrorAction Stop
        }

        $jwkObject = $null
        if ($certShouldBeReturned) {
            $jwkObject = [PSCustomObject][ordered]@{kty = "RSA"
                use                                     = $publicKeyUse
                e                                       = $encodedExponent
                n                                       = $encodedModulus
                kid                                     = $encodedThumbprint
                x5t                                     = $encodedThumbprint
                x5c                                     = $X509CertificateChain
            }
        }
        else {
            $jwkObject = [PSCustomObject][ordered]@{kty = "RSA"
                use                                     = $publicKeyUse
                e                                       = $encodedExponent
                n                                       = $encodedModulus
                kid                                     = $encodedThumbprint
            }
        }

        if ($PSCmdlet.ParameterSetName -eq "JSON") {
            [string]$jwkString = ""
            if ($PSBoundParameters.ContainsKey("Compress")) {
                $jwkString = $jwkObject | ConvertTo-Json -Depth 25 -Compress
            }
            else {
                $jwkString = $jwkObject | ConvertTo-Json -Depth 25
            }
            return $jwkString
        }

        return $jwkObject
    }
}

function New-JwtRsaSignature
{
    <#
        NOTES:  For certs to be useable by this method you must set the CSP to the signing certificate to be'Microsoft Enhanced RSA and AES Cryptographic Provider'.
                The following certutil command demonstrates this:
                certutil.exe -csp "Microsoft Enhanced RSA and AES Cryptographic Provider" -importpfx <target cert path> NoExport
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=0)]
        [ValidateLength(16,8192)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory=$true,Position=1)][Alias("Certificate", "Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,

        [Parameter(Position=2,Mandatory=$true)]
        [ValidateSet("SHA256","SHA384","SHA512")]
        [String]$HashAlgorithm,

        [Parameter(Position=3,Mandatory=$false)]
        [Switch]$VerifyCertificate
    )

    PROCESS
    {
        [string]$stringSig = ""

        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage

        [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken
        if (-not($isValidJwt))
        {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }
        else
        {
            if (($JsonWebToken.Split(".").Count) -ne 2)
            {
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }
        }

        $thumbprint = $SigningCertificate.Thumbprint

        if ($PSBoundParameters.ContainsKey($VerifyCertificate))
        {
            if (!($SigningCertificate.Verify()))
            {
                $verificationErrorMessage = "Certificate with thumbprint {0} failed verification. Check certificate chain, expiration, and CRL access." -f $thumbprint
                Write-Error -Exception ([CryptographicException]::new($verificationErrorMessage)) -Category SecurityError -ErrorAction Stop
            }
        }

        # Create an instance of the RSAPKCS1SignatureFormatter class that will ultimately be used to generate the signature:
        $rsaSigFormatter = [RSAPKCS1SignatureFormatter]::new()

        # Determine if executing context has read access to private key:
        [bool]$certHasPrivateKey = $false
        if ($null -ne $SigningCertificate.PrivateKey.KeyExchangeAlgorithm)
        {
            $certHasPrivateKey = $true
        }

        # Exception message for missing or inaccessible private key:
        $privateKeyErrorMessage = "Private key either not found or inaccessible for certificate with thumbprint {0}." -f $thumbprint

        if ($certHasPrivateKey)
        {
            try
            {
                $rsaSigFormatter.SetKey($SigningCertificate.PrivateKey)
            }
            catch
            {
                Write-Error -Exception ([CryptographicException]::new($privateKeyErrorMessage)) -Category SecurityError -ErrorAction Stop
            }
        }
        else
        {
            Write-Error -Exception ([CryptographicException]::new($privateKeyErrorMessage)) -Category SecurityError -ErrorAction Stop
        }

        # Set the RSA hash algorithm based on the RsaHashAlgorithm passed:
        $rsaSigFormatter.SetHashAlgorithm($HashAlgorithm.ToString())

        # Convert the incoming string $JsonWebToken  into a byte array:
        [byte[]]$message = [Encoding]::UTF8.GetBytes($JsonWebToken)

        # The byte array that will contain the resulting hash to be signed:
        [byte[]]$messageDigest = $null

        # Create a SHA256, SHA384 or SHA512 hash and assign it to the messageDigest variable:
        switch ($HashAlgorithm)
        {
            "SHA256"
            {
                $shaAlg = [SHA256]::Create()
                $messageDigest = $shaAlg.ComputeHash($message)
                break
            }
            "SHA384"
            {
                $shaAlg = [SHA384]::Create()
                $messageDigest = $shaAlg.ComputeHash($message)
                break
            }
            "SHA512"
            {
                $shaAlg = [SHA512]::Create()
                $messageDigest = $shaAlg.ComputeHash($message)
                break
            }
            default
            {
                $shaAlg = [SHA512]::Create()
                $messageDigest = $shaAlg.ComputeHash($message)
                break
            }
        }

        # Create the signature:
        [byte[]]$sigBytes = $null
        try
        {
            $sigBytes = $rsaSigFormatter.CreateSignature($messageDigest)
        }
        catch
        {
            $signingErrorMessage = "Unable to sign $JsonWebToken  with certificate with thumbprint {0}. Ensure that CSP for this certificate is 'Microsoft Enhanced RSA and AES Cryptographic Provider' and try again. Additional error info: {1}" -f $thumbprint, $_.Exception.Message
            Write-Error -Exception ([CryptographicException]::new($signingErrorMessage)) -Category SecurityError -ErrorAction Stop
        }

        # Return the Base64 URL encoded signature:
        $stringSig = ConvertTo-Base64UrlEncodedString -Bytes $sigBytes

        return $stringSig
    }
}
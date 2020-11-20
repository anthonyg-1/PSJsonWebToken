function Test-JwtRsaSignature
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=0)]
        [ValidateLength(16,8192)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory=$true,Position=1)][Alias("Certificate", "Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$VerificationCertificate,

        [Parameter(Position=2,Mandatory=$true)]
        [ValidateSet("SHA256","SHA384","SHA512")]
        [String]$HashAlgorithm,

        [Parameter(Position=3,Mandatory=$false)]
        [Switch]$VerifyCertificate
    )
    PROCESS
    {
        [bool]$sigVerifies = $false

        [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken -VerifySignaturePresent
        if (-not($isValidJwt))
        {
            $decodeExceptionMessage = "Unable to decode JWT."
            $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        $thumbprint = $VerificationCertificate.Thumbprint

        if ($PSBoundParameters.ContainsKey($VerifyCertificate))
        {
            if (!($VerificationCertificate.Verify()))
            {
                $verificationErrorMessage = "Certificate with thumbprint {0} failed verification. Check certificate chain, expiration, and CRL access." -f $thumbprint
                Write-Error -Exception ([CryptographicException]::new($verificationErrorMessage)) -Category SecurityError -ErrorAction Stop
            }
        }

        $headerPart = Get-JsonWebTokenHeader -JsonWebToken $JsonWebToken -AsEncodedString
        $payloadPart = Get-JsonWebTokenPayload -JsonWebToken $JsonWebToken -AsEncodedString
        $jwtSansSig = "{0}.{1}" -f $headerPart, $payloadPart

        $publicKey = $VerificationCertificate.PublicKey.Key

        try
        {
            [byte[]]$HeaderAndPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($jwtSansSig)
            [byte[]]$Signature = Get-JsonWebTokenSignature -JsonWebToken $JsonWebToken

            $sigVerifies = $publicKey.VerifyData($HeaderAndPayloadBytes, $Signature, $HashAlgorithm, [RSASignaturePadding]::Pkcs1)
        }
        catch
        {
            $sigVerifies = $false
        }

        return $sigVerifies
    }
}
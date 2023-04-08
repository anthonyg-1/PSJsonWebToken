function Test-JwtJwkSignature
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=0)]
        [ValidateLength(16,131072)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory=$true,Position=1)][Alias("jwk")][ValidateLength(12, 1073741791)][String]$JsonWebKey,

        [Parameter(Position=2,Mandatory=$true)][ValidateSet("SHA256","SHA384","SHA512")][String]$HashAlgorithm
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

        [PSCustomObject]$jwkData = $null
        try {
            $jwkData = $JsonWebKey | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            $ArgumentException = 'Invalid JSON Web Key passed. Ensure that JWK is formatted as proper JSON and try again.'
            Write-Error -Exception $ArgumentException -ErrorAction Stop
        }

        if (($null -eq $jwkData.kty) -or ($null -eq $jwkData.n) -or ($null -eq $jwkData.e)) {
            $ArgumentException = 'Invalid JSON Web Key passed. Ensure that a valid JWK is passed that contains the key type expressed as "kty", a public exponent as "e”, and modulus as "n" parameters per RFC 7517.'
            Write-Error -Exception $ArgumentException -ErrorAction Stop
        }

        if (($jwkData.kty).ToUpper() -ne "RSA") {
            $ArgumentException = 'Only a key type of RSA is supported at this time.'
            Write-Error -Exception $ArgumentException -ErrorAction Stop
        }

        $headerPart = Get-JsonWebTokenHeader -JsonWebToken $JsonWebToken -AsEncodedString
        $payloadPart = Get-JsonWebTokenPayload -JsonWebToken $JsonWebToken -AsEncodedString
        $jwtSansSig = "{0}.{1}" -f $headerPart, $payloadPart

        $publicKey = [RSACryptoServiceProvider]::new()
        try {
            $rsaParams = [RSAParameters]::new()
            $modulus = $jwkData.n | ConvertFrom-Base64UrlEncodedString -AsBytes -ErrorAction Stop
            $exponent = $jwkData.e | ConvertFrom-Base64UrlEncodedString -AsBytes -ErrorAction Stop
            $rsaParams.Modulus = $modulus
            $rsaParams.Exponent = $exponent
            $publicKey.ImportParameters($rsaParams)

            [byte[]]$HeaderAndPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($jwtSansSig)
            [byte[]]$Signature = Get-JsonWebTokenSignature -JsonWebToken $JsonWebToken -ErrorAction Stop

            $sigVerifies = $publicKey.VerifyData($HeaderAndPayloadBytes, $Signature, $HashAlgorithm, [RSASignaturePadding]::Pkcs1)
        }
        catch {
            $sigVerifies = $false
        }
        finally {
            $publicKey.Dispose()
        }

        return $sigVerifies
    }
}
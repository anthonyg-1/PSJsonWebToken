function New-JsonWebToken {
    <#
    .SYNOPSIS
        Generates a JSON Web Token.
    .DESCRIPTION
        Generates a signed JSON Web Token (JWS) with options for specifying a JWK URI in the header.
    .PARAMETER Claims
        The claims for the token expressed as a hash table.
    .PARAMETER SigningCertificate
        The X.509 certificate containing the private key that will sign the JSON Web Token.
    .PARAMETER TimeToLive
        The lifetime of the token expressed in seconds.
    .PARAMETER HashAlgorithm
        The hash algorthim for the signature. Acceptable values are SHA256, SHA384, and SHA512. Default value is SHA256.
    .PARAMETER JwkUri
        The URI for JSON Web Keys to verify the signature of the generated token. This is expressed as the attribute 'jku' in the header.
    .PARAMETER IncludeJwk
        Tells this function to include the public key of the X.509 certificate as a JSON Web Key in the header as the 'jwk' attribute.
    .PARAMETER X509Uri
        The URI for X.509 public key certificate or certificate chain to verify the signature of the generated token. This is expressed as the attribute 'x5u' in the header.
    .PARAMETER IncludeX509CertChain
        Tells the function to include the X.509 certificate chain as a collection of base64 encoded public keys in the header as the 'x5c' attribute.
    .PARAMETER NotBeforeSkew
        The amount of time in seconds that the not before claim (nbf) will be skewed in the past. This is useful in cases where identity providers and relying parties are not sharing the same source for time synchronization.
    .PARAMETER AddJtiClaim
        Adds a unique identifier for the token in the form of a jti claim to the payload.
    .PARAMETER Key
        This is the secret key used to generate an HMAC signature expressed as a string.
    .PARAMETER SecureKey
        This is the secret key used to generate an HMAC signature expressed as a System.Security.SecureString.
    .PARAMETER ExcludeDefaultClaims
        Excludes the nbf, iat, and exp default claims from the payload when using the HMAC parameter set.
    .PARAMETER NoSignature
        Tells this function to create an unsigned JWT. This is meant for security testing only and should never be used when a valid JWT is required!
    .PARAMETER CustomKeyIdentifier
        Tells this function to either add or override (in the case of the RSA parameter set) the kid attribute in the JWT header with the specified value.
    .EXAMPLE
        $claims = @{sub="$env:USERDOMAIN\$env:USERNAME";
                    iss="$env:COMPUTERNAME@$env:USERDNSDOMAIN"}

        $signingCertThumbprint = "706428667193645C3B4704FC824BEDFCEBB4F038"
        $certPath = Join-Path -Path Cert:\LocalMachine\My -ChildPath $signingCertThumbprint
        $signingCert = Get-Item -Path $certPath

        New-JsonWebToken -Claims $claims -SigningCertificate $signingCert -TimeToLive 300 -HashAlgorithm SHA256

        Generates a signed JSON Web Token using the certificate found in the local machine store with a thumbprint of 6C85DF2F915D0E28B719AEC188367092A0FD0CD2.
    .EXAMPLE
        $hmacJwt = New-JsonWebToken -Claims @{sub="tonyg"} -HashAlgorithm SHA256 -Key "secretkey" -TimeToLive 300

        Generates an HMAC-SHA256 signed JWT.
    .EXAMPLE
        $secureStringKey = "secretKey" | ConvertTo-SecureString -AsPlainText -Force
        $hmacJwt = New-JsonWebToken -Claims @{sub="tonyg"} -HashAlgorithm SHA256 -SecureKey $secureStringKey -TimeToLive 300

        Generates an HMAC-SHA256 signed JWT with the HMAC key passed as a SecureString.
    .EXAMPLE
        New-JsonWebToken -Claims @{sub="tonyg"} -NoSignature

        Creates an unsigned JWT for testing purposes.
    .OUTPUTS
        System.String

            The JSON Web Token is returned as a base64 URL encoded string.
    .LINK
        https://tools.ietf.org/html/rfc7519
        https://tools.ietf.org/html/rfc7515
        https://tools.ietf.org/html/rfc7517
        New-JsonWebKeySet
	Test-JsonWebToken
        ConvertFrom-EncodedJsonWebToken
        ConvertTo-SecureString
#>
    [CmdletBinding()]
    [Alias('njwt', 'NewJwt', 'CreateJwt')]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.Collections.Hashtable]$Claims,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("SHA256", "SHA384", "SHA512")]
        [String]$HashAlgorithm = "SHA256",

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateRange(1, 300)]
        [System.Int32]$NotBeforeSkew,

        [Parameter(Mandatory = $false, Position = 3)]
        [Switch]$AddJtiClaim,

        [Parameter(Mandatory = $true, ParameterSetName = "RSA", Position = 4)][Alias("Certificate", "Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateRange(1, 2147483647)]
        [System.Int32]$TimeToLive = 300,

        [Parameter(Mandatory = $false, ParameterSetName = "RSA", Position = 6)]
        [System.Uri]$JwkUri,

        [Parameter(Mandatory = $false, ParameterSetName = "RSA", Position = 7)]
        [Switch]$IncludeJwk,

        [Parameter(Mandatory = $false, ParameterSetName = "RSA", Position = 8)]
        [System.Uri]$X509Uri,

        [Parameter(Mandatory = $false, ParameterSetName = "RSA", Position = 8)]
        [Switch]$IncludeX509CertChain,

        [Parameter(Mandatory = $true, ParameterSetName = "HMAC", Position = 10)]
        [ValidateLength(1, 32768)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "HMACSecure", Position = 11)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$SecureKey,

        [Parameter(Mandatory = $false, Position = 12)][Alias('ExcludeDefaultDateClaims')][Switch]$ExcludeDefaultClaims,

        [Parameter(Mandatory = $false, ParameterSetName = "Unsigned", Position = 13)][Switch]$NoSignature,

        [Parameter(Mandatory = $false, Position = 14)][ValidateLength(0, 32768)][String]$CustomKeyIdentifier
    )

    PROCESS {
        [string]$jwt = ""

        # Construct payload for HMAC or RSA:
        [string]$payload = ""

        [HashTable]$_claims = $Claims

        if ($PSBoundParameters.ContainsKey("AddJtiClaim")) {
            if ($_claims.ContainsKey("jti")) {
                $_claims.Remove("jti") | Out-Null
            }
            $_claims.Add("jti", (New-Guid).Guid)
        }

        if ($PSBoundParameters.ContainsKey("ExcludeDefaultClaims")) {
            $payload = $_claims | ConvertTo-JwtPart
        }
        else {
            if ($PSBoundParameters.ContainsKey("NotBeforeSkew")) {
                $payload = New-JwtPayloadString -Claims $_claims -NotBeforeSkew $NotBeforeSkew
            }
            else {
                $payload = New-JwtPayloadString -Claims $_claims
            }
        }

        # Short circuit if NoSignature is called:
        if ($PSBoundParameters.ContainsKey("NoSignature")) {
            $headerTable = @{}
            if ($PSBoundParameters.ContainsKey("CustomKeyIdentifier")) {
                $headerTable = [ordered]@{typ = "JWT"; alg = "none"; kid = $CustomKeyIdentifier }
            }
            else {
                $headerTable = [ordered]@{typ = "JWT"; alg = "none" }
            }

            $header = $headerTable | ConvertTo-JwtPart
            $jwtSansSig = "{0}.{1}." -f $header, $payload
            return $jwtSansSig
        }

        if ($PSCmdlet.ParameterSetName -eq "RSA") {
            if ($null -eq $SigningCertificate.PrivateKey.KeyExchangeAlgorithm) {
                $cryptographicExceptionMessage = "Private key either not found or inaccessible for certificate with thumbprint: {0} " -f $SigningCertificate.Thumbprint
                $CryptographicException = New-Object -TypeName System.Security.Cryptography.CryptographicException -ArgumentList $cryptographicExceptionMessage
                Write-Error -Exception $CryptographicException -Category SecurityError -ErrorAction Stop
            }

            #1. Construct header:
            [string]$rsaAlg = ""
            switch ($HashAlgorithm) {
                "SHA256" { $rsaAlg = "RS256" }
                "SHA384" { $rsaAlg = "RS384" }
                "SHA512" { $rsaAlg = "RS512" }
                default { $rsaAlg = "RS256" }
            }

            # If CustomKeyIdentifier is called, exclude x5t from the header:
            $headerTable = @{}
            if ($PSBoundParameters.ContainsKey("CustomKeyIdentifier")) {
                $headerTable = [ordered]@{typ = "JWT"; alg = $rsaAlg; kid = $CustomKeyIdentifier }
            }
            else {
                $encodedThumbprint = Get-JwtKeyIdentifier -Certificate $SigningCertificate
                $headerTable = [ordered]@{typ = "JWT"; alg = $rsaAlg; x5t = $encodedThumbprint; kid = $encodedThumbprint }
            }

            if ($PSBoundParameters.ContainsKey("JwkUri")) {
                $headerTable.Add("jku", $JwkUri)
            }

            if ($PSBoundParameters.ContainsKey("IncludeJwk")) {
                $jwk = New-JsonWebKey -Certificate $SigningCertificate
                $headerTable.Add("jwk", $jwk)
            }

            if ($PSBoundParameters.ContainsKey("X509Uri")) {
                $headerTable.Add("x5u", $X509Uri)
            }

            if ($PSBoundParameters.ContainsKey("IncludeX509CertChain")) {
                $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                $chain.Build($SigningCertificate) | Out-Null
                $allCertsInChain = $chain.ChainElements | Select-Object -ExpandProperty Certificate

                $base64certs = @($allCertsInChain | Convert-X509CertificateToBase64 -NoFormat)

                $headerTable.Add("x5c", $base64certs)
            }

            $header = $headerTable | ConvertTo-JwtPart

            #2. Payload is constructed at beginning of PROCESS block.

            #3. Concatenate encoded header and payload seperated by a full stop:
            $jwtSansSig = "{0}.{1}" -f $header, $payload

            #4. Generate signature for concatenated header and payload:
            [string]$rsaSig = ""
            try {
                $rsaSig = New-JwtSignature -JsonWebToken $jwtSansSig -HashAlgorithm $HashAlgorithm -SigningCertificate $SigningCertificate
            }
            catch {
                Write-Error -Exception $_.Exception -Category InvalidArgument -ErrorAction Stop
            }

            #5. Construct jws:
            $jwt = "{0}.{1}" -f $jwtSansSig, $rsaSig
        }
        else {
            # Parameter set is HMAC of HMACSecure
            [string]$hmacKey = ""
            if ($PSCmdlet.ParameterSetName -eq "HMACSecure") {
                $networkCredential = [System.Net.NetworkCredential]::new("", $SecureKey)
                $hmacKey = $networkCredential.Password
            }
            else {
                $hmacKey = $Key
            }

            $hmacAlg = ""
            switch ($HashAlgorithm) {
                "SHA256" { $hmacAlg = "HS256" }
                "SHA384" { $hmacAlg = "HS384" }
                "SHA512" { $hmacAlg = "HS512" }
                default { $hmacAlg = "HS256" }
            }

            #1. Construct header:
            $headerTable = @{}
            if ($PSBoundParameters.ContainsKey("CustomKeyIdentifier")) {
                $headerTable = [ordered]@{typ = "JWT"; alg = $hmacAlg; kid = $CustomKeyIdentifier }
            }
            else {
                $headerTable = [ordered]@{typ = "JWT"; alg = $hmacAlg }
            }

            $header = $headerTable | ConvertTo-JwtPart

            #2. Payload is constructed at beginning of PROCESS block.

            #3. Concatenate encoded header and payload seperated by a full stop:
            $jwtSansSig = "{0}.{1}" -f $header, $payload

            #4. Generate signature for concatenated header and payload:
            $hmacSig = New-JwtSignature -JsonWebToken $jwtSansSig -Key $hmacKey -HashAlgorithm $HashAlgorithm

            #5. Construct jws:
            $jwt = "{0}.{1}" -f $jwtSansSig, $hmacSig
        }

        return $jwt
    }
}

function Test-JsonWebToken
{
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
    .PARAMETER SecretKey
        The secret key used to validate an HMAC signature expressed as a System.Security.SecureString
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

        Validates an HMAC-SHA256 signature only (not date range check) against a JWT with the HMAC key passed as a SecureString..
	.OUTPUTS
       System.Boolean
    .LINK
		https://tools.ietf.org/html/rfc7519
        New-JsonWebToken
        ConvertTo-SecureString
#>
    [CmdletBinding()]
    [Alias('tjwt', 'ValidateJwt')]
    [OutputType([System.Boolean])]
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=0)]
        [ValidateLength(16,8192)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory=$true,Position=2)]
        [ValidateSet("SHA256","SHA384","SHA512")]
        [String]$HashAlgorithm,

        [Parameter(Mandatory=$true,ParameterSetName="RSA",Position=3)][Alias("Certificate", "Cert")]
        [ValidateNotNullOrEmpty()][System.Security.Cryptography.X509Certificates.X509Certificate2]$VerificationCertificate,

        [Parameter(Mandatory=$true,ParameterSetName="HMAC",Position=3)]
        [ValidateLength(4,32768)]
        [String]$Key,

        [Parameter(Mandatory=$true,ParameterSetName="HMACSecure",Position=3)]
        [ValidateNotNullOrEmpty()]
        [System.Security.SecureString]$SecureKey,

        [Parameter(Mandatory=$false,Position=4)]
        [Switch]$SkipExpirationCheck
        )
	BEGIN
	{
		$decodeExceptionMessage = "Unable to decode JWT."
		$ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
	}
        PROCESS
        {
            [bool]$jwtIsValid = $false
            [bool]$signatureIsValid = $false
            [bool]$tokenIsNotExpired = $false

            [bool]$hasValidJwtStructure = Test-JwtStructure -JsonWebToken $JsonWebToken -VerifySignaturePresent
            if (-not($hasValidJwtStructure))
            {
                Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
            }

            $missingDateExceptionMessage = "Unable to validate token lifetime due to missing exp claim in payload. If signature validation only is required use the SkipExpirationCheck parameter."

            if ($PSCmdlet.ParameterSetName -eq "RSA")
            {
                try
                {
                    $signatureIsValid = Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -VerificationCertificate $VerificationCertificate
                }
                catch
                {
                    Write-Error -Exception $_ -Category InvalidResult -ErrorAction Stop
                }

                if ($PSBoundParameters.ContainsKey("SkipExpirationCheck"))
                {
                    $jwtIsValid = $signatureIsValid
                }
                else
                {
                    [bool]$tokenIsNotExpired = $false
                    try
                    {
                        $tokenIsNotExpired = Test-JwtDateRange -JsonWebToken $JsonWebToken -ErrorAction Stop
                    }
                    catch
                    {
                        $ArgumentException = New-Object -TypeName System.ArgumentException -Argument $missingDateExceptionMessage
                        Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
                    }

                    $jwtIsValid = $signatureIsValid -and $tokenIsNotExpired
                }
            }
            else # Parameter set is HMAC of HMACSecure
            {
                [string]$hmacKey = ""
                if ($PSCmdlet.ParameterSetName -eq "HMACSecure")
                {
                    $networkCredential = [System.Net.NetworkCredential]::new("", $SecureKey)
                    $hmacKey = $networkCredential.Password
                }
                else
                {
                    $hmacKey = $Key
                }

                try
                {
                    $signatureIsValid = Test-JwtSignature -JsonWebToken $JsonWebToken -HashAlgorithm $HashAlgorithm -Key $hmacKey
                }
                catch
                {
                    Write-Error -Exception $_ -Category InvalidResult -ErrorAction Stop
                }

                if ($PSBoundParameters.ContainsKey("SkipExpirationCheck"))
                {
                    $jwtIsValid = $signatureIsValid
                }
                else
                {
                    [bool]$tokenIsNotExpired = $false
                    try
                    {
                        $tokenIsNotExpired = Test-JwtDateRange -JsonWebToken $JsonWebToken -ErrorAction Stop
                    }
                    catch
                    {
                        $ArgumentException = New-Object -TypeName System.ArgumentException -Argument $missingDateExceptionMessage
                        Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
                    }

                    $jwtIsValid = $signatureIsValid -and $tokenIsNotExpired
                }
            }

            return $jwtIsValid
        }
}

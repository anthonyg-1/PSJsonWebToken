function Test-JwtDateRange
{
    <#
    .SYNOPSIS
        Validates a JSON Web Token date range.
    .DESCRIPTION
        Validates a JSON Web Token date range only (not signature).
    .PARAMETER JsonWebToken
        The JSON Web Token containing date range to be verified.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDI5MDE5MzUsIm5iZiI6MTYwMjkwMTkzNSwiZXhwIjoxNjAyOTAyMjM1LCJzdWIiOiJ1c2VyQGRvbWFpbi5jb20ifQ.a22mXBFpU3AT8pGu1bAmlpRxuQUzlyDYDI72FWEtyTA"
        Test-JwtDateRange -JsonWebToken $jwt

        Tests a JWT to determine if is within a currently valid date range.
    .OUTPUTS
        System.Boolean
    .NOTES
        This function requires a minimum of an exp (expiration) claim in the payload. If no exp claim exists an exception will be thrown.
        Both nbf (not before) and iat (issued at) are candidates for starting date ranges with nbf having precedence. These however are not required.
    .LINK
		https://tools.ietf.org/html/rfc7519
        Test-JwtSignature
#>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param (
            [Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=0)]
            [ValidateLength(16,8192)][Alias("JWT", "Token")][String]$JsonWebToken
          )

    BEGIN
    {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS
    {
        [bool]$dateRangeIsValid = $false

        [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken -VerifySignaturePresent
        if (-not($isValidJwt))
        {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        $payload = $JsonWebToken | Get-JsonWebTokenPayload

        [nullable[datetime]]$expirationDate = $null
        [nullable[datetime]]$notBefore = $null
        [nullable[datetime]]$issuedAt = $null

        [nullable[datetime]]$startDate = $null

        if ($payload.ContainsKey("exp"))
        {
            $expirationDate = Convert-EpochToDateTime -Epoch $payload["exp"]
        }

        if ($payload.ContainsKey("nbf"))
        {
            $notBefore = Convert-EpochToDateTime -Epoch $payload["nbf"]
        }

        if ($payload.ContainsKey("iat"))
        {
            $issuedAt = Convert-EpochToDateTime -Epoch $payload["iat"]
        }

        if ($null -eq $expirationDate)
        {
            $argumentExceptionMessage = "Missing exp claim in payload. Unable to validate token lifetime."
            $ArgumentException = New-Object -TypeName System.ArgumentException -ArgumentList $argumentExceptionMessage
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        if ($null -eq $notBefore)
        {
            if ($null -ne $issuedAt)
            {
                $startDate = $issuedAt
            }
        }
        else
        {
            $startDate = $notBefore
        }

        $nowUtc = (Get-Date).ToUniversalTime()

        if ($null -eq $startDate)
        {
            $dateRangeIsValid = $expirationDate -ge $nowUtc
        }
        else
        {
            if ($startDate -le $nowUtc)
            {
                $dateRangeIsValid = $expirationDate -ge $nowUtc
            }
        }

        return $dateRangeIsValid
    }
}
function Get-JwtExpiration {
    <#
    .SYNOPSIS
        Gets expiration information from a JSON Web Token.
    .DESCRIPTION
        Decodes the exp claim from a structurally valid JSON Web Token and returns calculated expiration properties.
        If the token does not contain an exp claim, no output is returned.
    .PARAMETER JsonWebToken
        A JSON Web Token that is to be decoded.
    .EXAMPLE
        $jwt | Get-JwtExpiration

        Returns ExpiresAt, ExpirationInMinutes, and, when the token expires in more than one hour, ExpirationInHours.
    .INPUTS
        System.String

            A string is received by the JsonWebToken parameter.
    .OUTPUTS
        System.Management.Automation.PSCustomObject

            An object containing calculated token expiration properties.
    .LINK
        ConvertFrom-EncodedJsonWebToken
        Get-JsonWebTokenPayload
#>
    [CmdletBinding()]
    [Alias('gjwte')]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateLength(16, 131072)][Alias("JWT", "Token")][String]$JsonWebToken
    )
    BEGIN {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS {
        [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken
        if (-not($isValidJwt)) {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        $deserializedPayload = $JsonWebToken | Get-JsonWebTokenPayload
        if (-not($deserializedPayload.ContainsKey("exp"))) {
            return
        }

        try {
            $expiration = Convert-EpochToDateTime -Epoch $deserializedPayload.exp
            $expirationInMinutes = [Math]::Floor(($expiration - [DateTime]::UtcNow).TotalMinutes)

            $jwtExpiration = [PSCustomObject][ordered]@{
                ExpiresAt           = $expiration
                ExpirationInMinutes = [int]$expirationInMinutes
            }

            if ($expirationInMinutes -gt 60) {
                $expirationInHours = [Math]::Round(($expirationInMinutes / 60), 1)
                $jwtExpiration | Add-Member -MemberType NoteProperty -Name ExpirationInHours -Value $expirationInHours
            }

            return $jwtExpiration
        }
        catch {
            Write-Error -Exception $_.Exception
        }
    }
}

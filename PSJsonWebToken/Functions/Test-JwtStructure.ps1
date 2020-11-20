function Test-JwtStructure
{
<#
    .SYNOPSIS
        Tests a JWT for structural validity.
    .DESCRIPTION
        Validates that a JSON Web Token is structurally valid by returing a boolean indicating if the passed JWT is valid or not.
    .PARAMETER JsonWebToken
        Contains the JWT to structurally validate.
    .PARAMETER VerifySignaturePresent
        Determines if the passed JWT has three parts (signature being the third).
    .EXAMPLE
        $jwtSansSig = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEyMzQ1Njc4OTAsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlfQ"
        Test-JwtStructure -JsonWebToken $jwtSansSig

        Validates the structure of a JWT without a signature.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Test-JwtStructure -JsonWebToken $jwt

        Validates the structure of a JWT with a signature.
    .NOTES
        By default a passed JWT's header and payload should base 64 URL decoded JSON. The VerifySignaturePresent switch ensures that all three parts exist seperated by a full-stop (header, payload, signature).
    .OUTPUTS
        System.Boolean
    .LINK
        https://tools.ietf.org/html/rfc7519
        https://en.wikipedia.org/wiki/RSA_(cryptosystem)
		https://en.wikipedia.org/wiki/HMAC
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param ( [Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=0)][ValidateLength(16,8192)][System.String]$JsonWebToken,

            [Parameter(Mandatory=$false,ValueFromPipeline=$false,Position=1)][Switch]$VerifySignaturePresent
    )
     PROCESS
     {
        $arrayCellCount = $JsonWebToken.Split(".") | Measure-Object | Select-Object -ExpandProperty Count

        if ($PSBoundParameters.ContainsKey("VerifySignaturePresent"))
        {
            if ($arrayCellCount -lt 3)
            {
                return $false
            }
            else
            {
                $jwtSignature = $JsonWebToken.Split(".")[2]

                if ($jwtSignature.Length -le 8)
                {
                    return $false
                }
            }
        }
        else
        {
            if ($arrayCellCount -lt 2)
            {
                return $false
            }
        }

        # Test deserialization against header:
        $jwtHeader = $JsonWebToken.Split(".")[0]

        if ($jwtHeader.Length -le 8)
        {
            return $false
        }

        [string]$jwtHeaderDecoded = ""
        try
        {
            $jwtHeaderDecoded = $jwtHeader | ConvertFrom-Base64UrlEncodedString
        }
        catch
        {
            return $false
        }

        try
        {
            $jwtHeaderDecoded | ConvertFrom-Json -ErrorAction Stop | Out-Null
        }
        catch
        {
            return $false
        }

        # Test deserialization against payload:
        $jwtPayload = $JsonWebToken.Split(".")[1]

        if ($jwtPayload.Length -le 8)
        {
            return $false
        }

        [string]$jwtPayloadDecoded = ""
        try
        {
            $jwtPayloadDecoded = $jwtPayload | ConvertFrom-Base64UrlEncodedString
        }
        catch
        {
            return $false
        }

        try
        {
            $jwtPayloadDecoded | ConvertFrom-Json -ErrorAction Stop | Out-Null
        }
        catch
        {
            return $false
        }

        return $true
    }
}

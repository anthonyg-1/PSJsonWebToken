function ConvertFrom-EncodedJsonWebToken {
    <#
    .SYNOPSIS
        Decodes a JSON Web Token.
    .DESCRIPTION
        Decodes a structurally valid JSON Web Token, specifically the header and the payload. This function does not validate a JSON Web Token, it merely decodes the token for purposes of viewing the claims in the header and payload segments.
    .PARAMETER JsonWebToken
        A signed JSON Web Token that is to be decoded.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCNTMjU2IjoiYklYZkw1RmREaWkzR2E3QmlEWndrcUQ5RE5JIiwiamt1IjoiaHR0cHM6Ly9xYS5pZHBzcnYuZm1nbG9iYWwuY29tL0FjY291bnQvSndrQ29sbGVjdGlvbiJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9naXZlbm5hbWUiOiJUb255IiwiaXNzIjoiaHR0cHM6Ly9xYS5pZHBzcnYuZm1nbG9iYWwuY29tIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvc3VybmFtZSI6Ikd1aW1lbGxpIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9hdXRoZW50aWNhdGlvbm1ldGhvZCI6Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9hdXRoZW50aWNhdGlvbm1ldGhvZC91bnNwZWNpZmllZCIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWVpZGVudGlmaWVyIjoidG9ueS5ndWltZWxsaUB5YWhvby5jb20iLCJhdWQiOiJ1cm46Zm1nOmlkZW50aXR5c2VydmVyLy9xYSIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvYXV0aGVudGljYXRpb25pbnN0YW50IjoiNy81LzIwMTYgOToxNjozMyBBTSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2VtYWlsYWRkcmVzcyI6InRvbnkuZ3VpbWVsbGlAeWFob28uY29tIiwiaWRlbnRpdHlwcm92aWRlciI6Imh0dHBzOi8vc3NvMi1zdGcuZm1nbG9iYWwuY29tIiwianRpIjoiNmI1ZGY4NjBGNDUxNDlEZjhERUZEM0NBZDFiRjA0ZjMiLCJpYXQiOjE0Njc3MjQ1OTksIm5iZiI6MTQ2NzcyNDU2OSwiZXhwIjoxNDY3NzI0ODk5fQ.RA3F6deEmZlq3RL2NDF07Nv5SrrY31Qfw1LfVoxNmdXlPcai1UH9ad80Oq66sMyJUMOtXMOA5RkwRZQ6L5gNFTAIApDjAlBFte1d5ziCSjBhxYzMZ-f_pFeBOmsMsSI5-BaAInYch7usZ2efEP8AdYKrZdkO5bgovL-7WD0Ts9gjVssWN_uhIcj-mM67xHartinKstPXUB4LUrJHHOoORCChs1eNS5xTq6q1xoPj-dYmlC56OaHKuzqUy9iByWssZ-0_DC6EfwIOqL4i43sNXPrSuDAisGPd_pxnYzqgdPAaWj9WTae7X1VHzvCiz21V7TGvDj37cwiXHj2dT93vAQ"

        ConvertFrom-EncodedJsonWebToken -JsonWebToken $jwt

        Decodes the JSON Web Token defined in the $jwt variable.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCNTMjU2IjoiYklYZkw1RmREaWkzR2E3QmlEWndrcUQ5RE5JIiwiamt1IjoiaHR0cHM6Ly9xYS5pZHBzcnYuZm1nbG9iYWwuY29tL0FjY291bnQvSndrQ29sbGVjdGlvbiJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9naXZlbm5hbWUiOiJUb255IiwiaXNzIjoiaHR0cHM6Ly9xYS5pZHBzcnYuZm1nbG9iYWwuY29tIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvc3VybmFtZSI6Ikd1aW1lbGxpIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9hdXRoZW50aWNhdGlvbm1ldGhvZCI6Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9hdXRoZW50aWNhdGlvbm1ldGhvZC91bnNwZWNpZmllZCIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWVpZGVudGlmaWVyIjoidG9ueS5ndWltZWxsaUB5YWhvby5jb20iLCJhdWQiOiJ1cm46Zm1nOmlkZW50aXR5c2VydmVyLy9xYSIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvYXV0aGVudGljYXRpb25pbnN0YW50IjoiNy81LzIwMTYgOToxNjozMyBBTSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2VtYWlsYWRkcmVzcyI6InRvbnkuZ3VpbWVsbGlAeWFob28uY29tIiwiaWRlbnRpdHlwcm92aWRlciI6Imh0dHBzOi8vc3NvMi1zdGcuZm1nbG9iYWwuY29tIiwianRpIjoiNmI1ZGY4NjBGNDUxNDlEZjhERUZEM0NBZDFiRjA0ZjMiLCJpYXQiOjE0Njc3MjQ1OTksIm5iZiI6MTQ2NzcyNDU2OSwiZXhwIjoxNDY3NzI0ODk5fQ.RA3F6deEmZlq3RL2NDF07Nv5SrrY31Qfw1LfVoxNmdXlPcai1UH9ad80Oq66sMyJUMOtXMOA5RkwRZQ6L5gNFTAIApDjAlBFte1d5ziCSjBhxYzMZ-f_pFeBOmsMsSI5-BaAInYch7usZ2efEP8AdYKrZdkO5bgovL-7WD0Ts9gjVssWN_uhIcj-mM67xHartinKstPXUB4LUrJHHOoORCChs1eNS5xTq6q1xoPj-dYmlC56OaHKuzqUy9iByWssZ-0_DC6EfwIOqL4i43sNXPrSuDAisGPd_pxnYzqgdPAaWj9WTae7X1VHzvCiz21V7TGvDj37cwiXHj2dT93vAQ"

        ConvertFrom-EncodedJsonWebToken -JsonWebToken $jwt | Select-Object -ExpandProperty Payload | ConvertFrom-Json

        Decodes the JSON Web Token defined in the $jwt variable, expands the Payload segment and deserializes it via the ConvertFrom-Json cmdlet.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCNTMjU2IjoiYklYZkw1RmREaWkzR2E3QmlEWndrcUQ5RE5JIiwiamt1IjoiaHR0cHM6Ly9xYS5pZHBzcnYuZm1nbG9iYWwuY29tL0FjY291bnQvSndrQ29sbGVjdGlvbiJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9naXZlbm5hbWUiOiJUb255IiwiaXNzIjoiaHR0cHM6Ly9xYS5pZHBzcnYuZm1nbG9iYWwuY29tIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvc3VybmFtZSI6Ikd1aW1lbGxpIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9hdXRoZW50aWNhdGlvbm1ldGhvZCI6Imh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9hdXRoZW50aWNhdGlvbm1ldGhvZC91bnNwZWNpZmllZCIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL25hbWVpZGVudGlmaWVyIjoidG9ueS5ndWltZWxsaUB5YWhvby5jb20iLCJhdWQiOiJ1cm46Zm1nOmlkZW50aXR5c2VydmVyLy9xYSIsImh0dHA6Ly9zY2hlbWFzLm1pY3Jvc29mdC5jb20vd3MvMjAwOC8wNi9pZGVudGl0eS9jbGFpbXMvYXV0aGVudGljYXRpb25pbnN0YW50IjoiNy81LzIwMTYgOToxNjozMyBBTSIsImh0dHA6Ly9zY2hlbWFzLnhtbHNvYXAub3JnL3dzLzIwMDUvMDUvaWRlbnRpdHkvY2xhaW1zL2VtYWlsYWRkcmVzcyI6InRvbnkuZ3VpbWVsbGlAeWFob28uY29tIiwiaWRlbnRpdHlwcm92aWRlciI6Imh0dHBzOi8vc3NvMi1zdGcuZm1nbG9iYWwuY29tIiwianRpIjoiNmI1ZGY4NjBGNDUxNDlEZjhERUZEM0NBZDFiRjA0ZjMiLCJpYXQiOjE0Njc3MjQ1OTksIm5iZiI6MTQ2NzcyNDU2OSwiZXhwIjoxNDY3NzI0ODk5fQ.RA3F6deEmZlq3RL2NDF07Nv5SrrY31Qfw1LfVoxNmdXlPcai1UH9ad80Oq66sMyJUMOtXMOA5RkwRZQ6L5gNFTAIApDjAlBFte1d5ziCSjBhxYzMZ-f_pFeBOmsMsSI5-BaAInYch7usZ2efEP8AdYKrZdkO5bgovL-7WD0Ts9gjVssWN_uhIcj-mM67xHartinKstPXUB4LUrJHHOoORCChs1eNS5xTq6q1xoPj-dYmlC56OaHKuzqUy9iByWssZ-0_DC6EfwIOqL4i43sNXPrSuDAisGPd_pxnYzqgdPAaWj9WTae7X1VHzvCiz21V7TGvDj37cwiXHj2dT93vAQ"

        ConvertFrom-EncodedJsonWebToken -JsonWebToken $jwt | Select IssuedAt, NotBefore

        Returns the iat and exp claims in the payload deserialized as "IssuedAt" and "Expiration" as DateTime.
    .INPUTS
        System.String

            A string is received by the JsonWebToken parameter.
    .OUTPUTS
        PSJsonWebToken.DecodedJsonWebToken

            An object containing the decoded header and payload segments. The signature segment remains encoded.    .
    .LINK
		https://tools.ietf.org/html/rfc7519
        New-JsonWebToken
        ConvertFrom-Json
#>
    [CmdletBinding()]
    [Alias('jwtd', 'djwt', 'DecodeJwt')]
    [OutputType([PSJsonWebToken.DecodedJsonWebToken])]
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

        $deserializedHeader = $JsonWebToken | Get-JsonWebTokenHeader
        $deserializedPayload = $JsonWebToken | Get-JsonWebTokenPayload

        $serializedHeader = $deserializedHeader | ConvertTo-Json -Compress
        $serializedPayload = $deserializedPayload | ConvertTo-Json -Compress
        $signatureString = $JsonWebToken.Split(".")[2]

        $decodedJsonWebToken = [PSJsonWebToken.DecodedJsonWebToken]::new()
        $decodedJsonWebToken.Header = $serializedHeader
        $decodedJsonWebToken.Payload = $serializedPayload
        $decodedJsonWebToken.Signature = $signatureString

        [bool]$containsPotentialThumbprint = $false
        [string]$encodedThumbprint = ""
        [string]$decodedThumbprint = ""

        if ($deserializedHeader.ContainsKey("x5t")) {
            $containsPotentialThumbprint = $true
            $encodedThumbprint = $deserializedHeader.x5t
        }
        elseif ($deserializedHeader.ContainsKey("kid")) {
            $containsPotentialThumbprint = $true
            $encodedThumbprint = $deserializedHeader.kid
        }

        if ($containsPotentialThumbprint) {
            [bool]$thumbprintDecodes = $false
            try {
                $decodedThumbprint = ConvertFrom-EncodedJwtThumbprint -EncodedThumbprint $encodedThumbprint
                $thumbprintDecodes = $true
            }
            catch {
                $thumbprintDecodes = $false
            }

            if ($thumbprintDecodes) {
                $decodedJsonWebToken | Add-Member -MemberType NoteProperty -Name SigningCertificateThumbprint -Value $decodedThumbprint
            }
        }

        if ($deserializedPayload.ContainsKey("nbf")) {
            try {
                $notBefore = Convert-EpochToDateTime -Epoch $deserializedPayload.nbf
                $decodedJsonWebToken | Add-Member -MemberType NoteProperty -Name NotBefore -Value $notBefore
            }
            catch {
                Write-Error -Exception $_.Exception
            }
        }

        if ($deserializedPayload.ContainsKey("iat")) {
            try {
                $issuedAt = Convert-EpochToDateTime -Epoch $deserializedPayload.iat
                $decodedJsonWebToken | Add-Member -MemberType NoteProperty -Name IssuedAt -Value $issuedAt
            }
            catch {
                Write-Error -Exception $_.Exception
            }
        }

        if ($deserializedPayload.ContainsKey("exp")) {
            try {
                $expiration = Convert-EpochToDateTime -Epoch $deserializedPayload.exp
                $decodedJsonWebToken | Add-Member -MemberType NoteProperty -Name Expiration -Value $expiration
            }
            catch {
                Write-Error -Exception $_.Exception
            }
        }

        return $decodedJsonWebToken
    }
}

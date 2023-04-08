function Show-EncodedJwt {
    <#
    .SYNOPSIS
        Displays an encoded JWT with the individual parts in color.
    .DESCRIPTION
        Displays an encoded JWT with the individual parts in color for easy viewing. Note that this advanced function is not meant to send any data and/or objects down the pipeline.
    .PARAMETER JsonWebToken
        The JSON Web Token to be displayed.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
        $jwt | Show-EncodedJwt

        Displays an encoded JSON Web Token with the header in red, the body in cyan, and green for the signature.
    .INPUTS
        System.String
            A string is received by the JsonWebToken parameter.
    .OUTPUTS
        None
        This cmdlet returns no output. It sends the objects to the host. The host displays the objects this cmdlet sends to it.
    .LINK
        https://tools.ietf.org/html/rfc7519
#>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateLength(16, 131072)][Alias("JWT", "Token")][String]$JsonWebToken
    )
    BEGIN {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS {
        [bool]$hasValidJwtStructure = Test-JwtStructure -JsonWebToken $JsonWebToken -VerifySignaturePresent
        if (-not($hasValidJwtStructure)) {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        # Get the header, payload, and signature as their already encoded strings:
        $header = Get-JsonWebTokenHeader -JsonWebToken $JsonWebToken -AsEncodedString
        $payload = Get-JsonWebTokenPayload -JsonWebToken $JsonWebToken -AsEncodedString
        $signature = Get-JsonWebTokenSignature -JsonWebToken $JsonWebToken -AsEncodedString

        # Write each of the three JWT parts seperated by periods:
        Write-Host -Object $header -ForegroundColor Red -NoNewline
        Write-Host -Object "." -ForegroundColor Yellow -NoNewline
        Write-Host -Object $payload -ForegroundColor Cyan -NoNewline
        Write-Host -Object "." -ForegroundColor Yellow -NoNewline
        Write-Host -Object $signature -ForegroundColor Green
    }
}

function Show-DecodedJwt {
    <#
    .SYNOPSIS
        Displays a JSON Web Token header and payload in color.
    .DESCRIPTION
         Displays a JSON Web Token header and payload in color for easy viewing. Note that this advanced function is not meant to send any data and/or objects down the pipeline.
    .PARAMETER JsonWebToken
        The JSON Web Token to be decoded and displayed.
    .PARAMETER SendToClipboard
        Tells the function to send the decoded JSON Web Token to the clipboard.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
        $jwt | Show-DecodedJwt

        Displays a decoded JSON Web Token with the header in red, the body in cyan/blue, and a green placeholder for the signature.
  .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
        $jwt | Show-DecodedJwt -SendToClipboard

        Displays a decoded JSON Web Token with the header in red, the body in cyan/blue, and a green placeholder for the signature as well as sending the decoded JSON Web Token to the clipboard.
    .INPUTS
        System.String
            A string is received by the JsonWebToken parameter.
    .OUTPUTS
        None
            This cmdlet returns no output. It sends text output to the host and optionally the clipboard.
    .LINK
        https://tools.ietf.org/html/rfc7519
#>
    [CmdletBinding()]
    [Alias('sjwt')]
    [OutputType([System.Boolean])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateLength(16, 131072)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1,
            ValueFromPipelineByPropertyName = $false)][Alias("clip", "ToClipboard", "c")][Switch]$SendToClipboard
    )
    BEGIN {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS {
        [bool]$hasValidJwtStructure = Test-JwtStructure -JsonWebToken $JsonWebToken
        if (-not($hasValidJwtStructure)) {
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        $arrayCellCount = $JsonWebToken.Split(".") | Measure-Object | Select-Object -ExpandProperty Count

        if ($arrayCellCount -lt 3) {
            $decodeExceptionMessage = "Unable to decode JWT."
            $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
            Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
        }

        # Get the header and payload as hashtables:
        $header = Get-JsonWebTokenHeader -JsonWebToken $JsonWebToken
        $payload = Get-JsonWebTokenPayload -JsonWebToken $JsonWebToken

        $headerJson = $header | ConvertTo-Json -Depth 25
        $payloadJson = $payload | ConvertTo-Json -Depth 25
        $signaturePlaceholderString = "[Signature]"

        if ($PSBoundParameters.ContainsKey("SendToClipboard")) {
            [string]$jwtStringForClipboard = ""

            if ((($JsonWebToken.Split(".")[2]).Length -gt 8)) {
                $jwtStringForClipboard = "{0}.{1}.{2}" -f $headerJson, $payloadJson, $signaturePlaceholderString
            }
            else {
                $jwtStringForClipboard = "{0}.{1}" -f $headerJson, $payloadJson
            }

            $jwtStringForClipboard | Set-Clipboard
        }

        # Serialize the hashtables into JSON and output via Write-Host
        Write-Host -Object ""
        $headerJson | Write-Host -ForegroundColor Red -NoNewline
        Write-Host -Object "." -ForegroundColor Yellow -NoNewline
        $payloadJson | Write-Host -ForegroundColor Cyan -NoNewline
        Write-Host -Object "." -ForegroundColor Yellow -NoNewline
        if ((($JsonWebToken.Split(".")[2]).Length -gt 8)) {
            Write-Host -Object $signaturePlaceholderString -ForegroundColor Green
        }
        Write-Host -Object ""
    }
}

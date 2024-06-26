function Convert-X509CertificateToBase64 {
    <#
    .SYNOPSIS
        Converts an X509Certificate2 to Base64.
    .DESCRIPTION
        Converts an X509Certificate2 to Base64 string containing only the public key.
    .PARAMETER Certificate
        The X509Certificate2 object to convert to Base64.
    .PARAMETER NoFormat
        Returns the certificate as Base64 without any header, footer, or carriage returns.
    .EXAMPLE
        Get-PfxCertificate -PSPath ./cert.cer | Convert-X509CertificateToBase64 -NoFormat

        Removes header, footer and carriage returns from an incoming certificate.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate

            A X509Certificate value is received by the Certificate parameter.
    .OUTPUTS
        System.String
    .LINK
        Get-PfxCertificate
#>
    [CmdletBinding()]
    [Alias('cx509tob64', 'cx509ctob64')]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0)]
        [ValidateNotNullOrEmpty()][Alias('Cert', 'c', 'x509', 'x509c')]
        [X509Certificate]$Certificate,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            Position = 1)]
        [Alias('nf')][Switch]$NoFormat
    )
    PROCESS {
        try {
            [string]$certString = ""

            $base64Cert = "{0}{1}" -f ([System.Convert]::ToBase64String($Certificate.Export([X509ContentType]::Cert)), $null)

            if ($PSBoundParameters.ContainsKey("NoFormat")) {
                $certString = $base64Cert
            }
            else {
                $header = "-----BEGIN CERTIFICATE-----"
                $footer = "-----END CERTIFICATE-----"

                $chunkSize = 64
                $stringLength = $base64Cert.Length

                $formattedResult = @()
                $formattedResult += $header

                for ($i = 0; $i -lt $stringLength; $i += $chunkSize) {
                    if ($i + $chunkSize -gt $stringLength) { $chunkSize = $stringLength - $i }
                    $formattedResult += $base64Cert.Substring($i, $chunkSize).Trim()
                }

                $formattedResult += $footer

                $certString = $formattedResult -join "`r`n"
            }
        }
        catch {
            $CryptographicExceptionMessage = "Unable to export certificate to Base64. Exception details: {0}" -f $_.Exception
            $CryptographicException = New-Object -TypeName System.Security.Cryptography.CryptographicException -ArgumentList $CryptographicExceptionMessage
            Write-Error -Exception $CryptographicException -Category InvalidResult -ErrorAction Stop
        }

        return $certString
    }
}

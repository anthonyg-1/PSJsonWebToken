function Get-JwtKeyIdentifier {
    <#
    .SYNOPSIS
        Gets a JWT key identifier from an X509 certificate.
    .DESCRIPTION
        Gets a JWT key identifier from an X509 certificate hash value as a base64 URL encoded string that can be used to populate a JWT header kid parameter.
    .PARAMETER Certificate
        The certificate that the JWT key identifier will be obtained from.
    .EXAMPLE
        $cert = Get-PfxCertificate -FilePath ./mycert.pfx
        $keyIdentifier = $cert | Get-JwtKeyIdentifier
        $jwtHeader = [ordered]@{typ="JWT";alg="RS256";kid=$keyIdentifier} | ConvertTo-JwtPart

        Obtains a JWT key identifier from certificate file mycert.pfx and creates a JWT header populating the kid property with the retrieved value.
    .INPUTS
        System.Security.Cryptography.X509Certificates.X509Certificate2
    .OUTPUTS
        System.String
    .LINK
        https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4
        ConvertTo-JwtPart
        Get-Item
#>

    [CmdletBinding()]
    [Alias('gjwtkid')]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)][Alias("Cert")]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    PROCESS {
        [string]$keyIdentifier = ""

        $keyIdentifier = ConvertTo-Base64UrlEncodedString -Bytes $Certificate.GetCertHash()

        return $keyIdentifier
    }
}

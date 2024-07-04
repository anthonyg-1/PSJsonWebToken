#
# Module manifest for module 'PSJsonWebToken'
#
# Generated by: Tony Guimelli
#
# Generated on: 11/19/2020
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule           = '.\PSJsonWebToken.psm1'

    # Version number of this module.
    ModuleVersion        = '1.15.0'

    # Compatibility
    CompatiblePSEditions = 'Desktop', 'Core'

    # ID used to uniquely identify this module
    GUID                 = '75bb4722-7360-4260-be02-20e413528df2'

    # Author of this module
    Author               = 'Tony Guimelli'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Description of the functionality provided by this module
    Description          = 'This PowerShell module contains functions that facilitate the creation, validation, and decoding of JWTs (JSON Web Tokens) as well as the creation of JWKs (JSON Web Keys).'

    # Functions to export from this module
    FunctionsToExport    = 'ConvertTo-Base64UrlEncodedString', 'ConvertFrom-Base64UrlEncodedString', 'Get-JwtKeyIdentifier', 'New-JwtSignature', 'New-JsonWebToken', 'Test-JsonWebToken', 'ConvertFrom-EncodedJsonWebToken', 'New-JsonWebKeySet', 'New-JsonWebKey', 'Get-JsonWebTokenHeader', 'Get-JsonWebTokenPayload', 'Get-JsonWebTokenSignature', 'ConvertTo-JwtPart', 'Test-JwtStructure', 'Test-JwtSignature', 'Convert-DateTimeToEpoch', 'Convert-EpochToDateTime', 'Test-JwtDateRange', 'Convert-X509CertificateToBase64', 'Get-JwkCollection', 'Show-DecodedJwt', 'Show-EncodedJwt', 'Test-JwtSecret', 'Convert-JwkToPem'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = 'jwtd', 'djwt', 'njwt', 'NewJwt', 'CreateJwt', 'gjwtkid', 'tjwt', 'sjwt', 'ValidateJwt', 'DecodeJwt', 'njwks', 'CreateJwkSet', 'njwk', 'CreateJwk', 'b64e', 'Encode', 'b64d', 'Decode', 'GetEpoch', 'gjwth', 'gjwtp', 'gjwtsig', 'gjwkc', 'tjwts', 'cjwk', 'cx509tob64', 'cx509ctob64'

    # List of all files packaged with this module
    FileList             = 'PSJsonWebToken.psd1', 'PSJsonWebToken.psm1'

    PrivateData          = @{
        PSData = @{
            Tags       = @('jwt', 'jwk', 'jsonwebtoken', 'jsonwebkey', 'oidc', 'openidconnect')
            LicenseUri = 'https://github.com/anthonyg-1/PSJsonWebToken/blob/main/LICENSE'
            ProjectUri = 'https://github.com/anthonyg-1/PSJsonWebToken'
        }
    }
}

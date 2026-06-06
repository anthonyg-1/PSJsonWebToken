function Get-JsonWebTokenHeader {
    <#
    .SYNOPSIS
        Gets the JSON Web Token header from the passed JWT.
    .DESCRIPTION
        Deserializes a JSON Web Token header to a System.Collections.HashTable by default. Optionally a string (base 64 encoded or JSON) is returned depending on parameters chosen.
    .PARAMETER JsonWebToken
        Specifies the The JSON Web Token to get the header from.
    .PARAMETER AsEncodedString
        Returns the header as a base 64 URL encoded string.
    .PARAMETER AsJson
        Returns the header as a compressed JSON string.
    .PARAMETER Formatted
        Returns the header as a formatted (indented) JSON string. Must be used with -AsJson.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        $jwt | Get-JsonWebTokenHeader

        Returns the header from the passed JWT as a Hashtable.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Get-JsonWebTokenHeader -JsonWebToken $jwt -AsEncodedString

        Returns the encoded header from the passed JWT.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Get-JsonWebTokenHeader -JsonWebToken $jwt -AsJson

        Returns the decoded header from the passed JWT as a compressed JSON string.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Get-JsonWebTokenHeader -JsonWebToken $jwt -AsJson -Formatted

        Returns the decoded header from the passed JWT as a formatted JSON string.
    .INPUTS
        System.String

            A String is received by the JsonWebToken parameter.
    .OUTPUTS
        System.Collections.Hashtable or System.String
    .LINK
	New-JsonWebToken
        Test-JsonWebToken
        Get-JsonWebTokenPayload
        Get-JsonWebTokenSignature
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    [Alias('gjwth', 'Get-JwtHeader')]
    [OutputType([System.Collections.Hashtable])]
    [OutputType([System.String], ParameterSetName = "Base64")]
    [OutputType([System.String], ParameterSetName = "JSON")]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateLength(16, 131072)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(ParameterSetName = "Base64", Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false, Position = 1)][Alias("AsIs")][switch]$AsEncodedString,

        [Parameter(ParameterSetName = "JSON", Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false, Position = 1)][Alias("json")][switch]$AsJson,

        [Parameter(ParameterSetName = "JSON", Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false, Position = 2)][switch]$Formatted
    )

    BEGIN {
        $decodeExceptionMessage = "Unable to decode JWT."
        $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList $decodeExceptionMessage
    }
    PROCESS {
        [bool]$isValidJwt = Test-JwtStructure -JsonWebToken $JsonWebToken
        if (-not($isValidJwt)) {
            Write-Error -Exception $ArgumentException -Category InvalidData -ErrorAction Stop
        }

        $jwtHeader = $JsonWebToken.Split(".")[0]

        if ($PSBoundParameters.ContainsKey("AsEncodedString")) {
            return $jwtHeader
        }
        elseif ($PSBoundParameters.ContainsKey("AsJson")) {
            if ($PSBoundParameters.ContainsKey("Formatted")) {
                return $jwtHeader | ConvertFrom-Base64UrlEncodedString | ConvertFrom-Json | ConvertTo-Json
            }
            else {
                return $jwtHeader | ConvertFrom-Base64UrlEncodedString
            }
        }
        else {
            [System.Collections.Hashtable]$jwtHeaderTable = $jwtHeader | ConvertFrom-Base64UrlEncodedString | ConvertFrom-Json | Convert-PSObjectToHashTable
            return $jwtHeaderTable
        }
    }
}

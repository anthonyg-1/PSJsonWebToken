function Get-JsonWebTokenPayload {
    <#
    .SYNOPSIS
        Gets the JSON Web Token payload from the passed JWT.
    .DESCRIPTION
        Deserializes a JSON Web Token payload to a System.Collections.HashTable by default. Optionally a string (base 64 encoded or JSON) is returned depending on parameters chosen.
    .PARAMETER JsonWebToken
        Specifies the The JSON Web Token to get the payload from.
    .PARAMETER AsEncodedString
        Returns the payload as a base 64 URL encoded string.
    .PARAMETER AsJson
        Returns the payload as a JSON string.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        $jwt | Get-JsonWebTokenPayload

        Returns the payload from the passed JWT as a Hashtable.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Get-JsonWebTokenPayload -JsonWebToken $jwt -AsEncodedString

        Returns the encoded payload from the passed JWT.
    .EXAMPLE
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Get-JsonWebTokenPayload -JsonWebToken $jwt -AsJson

        Returns the decoded payload from the passed JWT.
    .INPUTS
        System.String

            A String is received by the JsonWebToken parameter.
    .OUTPUTS
        System.Collections.Hashtable or System.String
    .LINK
	New-JsonWebToken
        Test-JsonWebToken
        Get-JsonWebTokenHeader
        Get-JsonWebTokenSignature
#>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    [Alias('gjwtp')]
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
            ValueFromPipelineByPropertyName = $false, Position = 1)][Alias("json")][switch]$AsJson
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

        $jwtPayload = $JsonWebToken.Split(".")[1]

        if ($PSBoundParameters.ContainsKey("AsEncodedString")) {
            return $jwtPayload
        }
        elseif ($PSBoundParameters.ContainsKey("AsJson")) {
            return $jwtPayload | ConvertFrom-Base64UrlEncodedString
        }
        else {
            [System.Collections.Hashtable]$jwtPayloadTable = $jwtPayload | ConvertFrom-Base64UrlEncodedString | ConvertFrom-Json -Depth 25 | Convert-PSObjectToHashTable
            return $jwtPayloadTable
        }
    }
}

function Get-JwkCollection {
    <#
    .SYNOPSIS
        Gets a collection of JSON Web Keys (JWKs) from a URI.
    .DESCRIPTION
        Gets a collection of JSON Web Keys (JWKs) from a well known openid configuration endpoint or URI containing only JSON Web Keys.
   .PARAMETER Uri
        Specifies the Uniform Resource Identifier (URI) containing the JSON Web Keys. Can be a well-known OpenID Connect discovery endpoint or a link containing the JWKs directly.
    .PARAMETER AsJson
        Tells the function to return JSON as opposed to an object.
    .PARAMETER IncludeX509Certificate
        If the JWK in the collection contains a populated x5c property, this parameter converts this value into an System.Security.Cryptography.X509Certificates.X509Certificate2 object. This parameter does not work with the AsJson parameter.
    .EXAMPLE
        $oidcUrl = 'https://accounts.google.com/.well-known/openid-configuration'
        Get-JwkCollection -Uri $oidcUrl

        Gets JSON Web Keys from google's well known openid configuration endpoint as objects.
    .EXAMPLE
        $jwkUrl = 'https://login.windows.net/common/discovery/keys'
        Get-JwkCollection -Uri $jwkUrl -AsJson

        Gets JSON Web Keys from Microsoft's JWK endpoint as JSON.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
        $jwkUri = "https://app.mycompany.com/common/discovery/keys"

        Get-JwkCollection -Uri $jwkUri -AsJson | ForEach-Object { Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -JsonWebKey $_ -SkipExpirationCheck }

        Attempts to validate a JSON Web Token signature against a collection of JSON Web Keys in https://app.mycompany.com/common/discovery/keys.
    .INPUTS
        System.Uri
    .OUTPUTS
        System.String or System.Management.Automation.PSCustomObject
    .LINK
        https://tools.ietf.org/html/rfc7517
        Test-JsonWebToken
        New-JsonWebKeySet

#>
    [CmdletBinding()]
    [Alias('gjwkc')]
    [OutputType([String[]], [PSCustomObject[]])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)][Alias('Url', 'u')][System.Uri]$Uri,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1)][Alias('aj', 'j', 'json')][Switch]$AsJson,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 2)][Alias('ic', 'IncludeCert', 'IncludeCertificate', 'cert')][Switch]$IncludeX509Certificate
    )
    PROCESS {
        $jwks = @()

        $response = $null

        try {
            $response = Invoke-RestMethod -Method Get -Uri $Uri -ErrorAction Stop
        }
        catch {
            Write-Error -Exception $_.Exception -ErrorAction Stop
        }

        if ($null -eq $response.keys) {
            if ($null -ne $response.jwks_uri) {
                try {
                    $jwkUri = [Uri]::new($response.jwks_uri)
                    $response = Invoke-RestMethod -Method Get -Uri $jwkUri -ErrorAction Stop
                }
                catch {
                    Write-Error -Exception $_.Exception -ErrorAction Stop
                }
            }
            else {
                $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList ("Zero JSON Web Keys found at {0}" -f $Uri)
                Write-Error -Exception $ArgumentException -ErrorAction Stop
            }
        }

        foreach ($key in $response.keys) {
            if (($null -eq $key.kty) -or ($null -eq $key.n) -or ($null -eq $key.e)) {
                $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList 'JSON Web Key schema validation failed. Ensure that a valid JWK is passed that contains the key type expressed as "kty", a public exponent as "e”, and modulus as "n" parameters per RFC 7517.'
                Write-Error -Exception $ArgumentException -ErrorAction Stop
            }
            else {
                if ($key.kty -eq "RSA") {
                    if ($PSBoundParameters.ContainsKey("AsJson")) {
                        $jwks += ($key | ConvertTo-Json)
                    }
                    else {
                        if ($PSBoundParameters.ContainsKey("IncludeX509Certificate")) {
                            if ($key.x5c) {
                                $certBytes = [Encoding]::ASCII.GetBytes($key.x5c)
                                $x509Cert = [X509Certificate2]::new($certBytes)

                                $keyHashTable = $key | Convert-PSObjectToHashTable
                                $keyHashTable.Add("X509Certificate", $x509Cert)

                                $augmentedKey = [PSCustomObject]$keyHashTable
                            }
                            $jwks += $augmentedKey
                        }
                        else {
                            $jwks += $key
                        }
                    }
                }
                else {
                    $ArgumentException = New-Object -TypeName ArgumentException -ArgumentList 'Only RSA JSON Web Keys are supported at this time.'
                    Write-Error -Exception $ArgumentException -ErrorAction Stop
                }
            }
        }
        return $jwks
    }
}

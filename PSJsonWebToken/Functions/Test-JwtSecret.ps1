
function Test-JwtSecret {
    <#
    .SYNOPSIS
        Attempts to obtain the secret for an HS256, HS384 or HS512-signed JSON Web Token.
    .DESCRIPTION
        Attempts to obtain the secret for an HS256, HS384 or HS512-signed JSON Web Token from a wordlist containing potential secrets.
    .PARAMETER JsonWebToken
        The target JSON Web Token to test the list of secrets against.
    .PARAMETER HashAlgorithm
        The RSA hash algorithm for the signature. Acceptable values are SHA256, SHA384, and SHA512. Default value is SHA256.
    .PARAMETER WordListFilePath
        The wordlist file containing typical passwords/secrets to test the JWT against.
    .EXAMPLE
       $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYxNDEwOTMsIm5iZiI6MTYwNjE0MTA5MywiZXhwIjoxNjA2MTQxMzkzLCJqdGkiOiI1Njk5YTBlYTk3YzM0Yzc2OTlkZGZlNzNmNTIzOTI1MiIsInN1YiI6InVzZXJuYW1lQGNvbXBhbnkuY29tIn0.Ej86QALzH37R1zB7QhwwYdFjXL1UhG2E3n6nezEYONY"
       $jwt | Test-JwtSecret -WordListFilePath ./wordlist.txt

       Tests an HMAC-SHA256 signed JWT signature against a wordlist.
    .EXAMPLE
        $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE2NzYzMDg2MTksIm5iZiI6MTY3NjMwODYxOSwiZXhwIjoxNjc2MzA4OTE5LCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSIsImp0aSI6ImVlODczMzc1MmQ0YTQxNzNiOTA0ODcxZjFjODMxNzQ2In0.rKDBCWkALz7FBTavX9G4HNnaLcyQY8i1WurAs1aQpfDA5Tmi3EtKn6K1k2OO9V-J-94t0ToaypxrtePyc0h8rA"
        $jwt | Test-JwtSecret -HashAlgorithm SHA512 -WordListFilePath ./wordlist.txt

        Tests an HMAC-SHA512 signed JWT signature against a wordlist.
    .INPUTS
        System.String
        A string is received by the JsonWebToken parameter.
    .OUTPUTS
       System.String
    .LINK
        https://tools.ietf.org/html/rfc7519
#>
    [CmdletBinding()]
    [Alias('tjwts')]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateLength(16, 8192)][Alias("JWT", "Token")][String]$JsonWebToken,

        [Parameter(Mandatory = $false, Position = 1)][ValidateSet("SHA256", "SHA384", "SHA512")][String]$HashAlgorithm = "SHA256",

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 2)][Alias("Path", "FilePath")]
        [ValidateScript({
                if ( -Not ($_ | Test-Path) ) {
                    $fileNotFoundExceptionMessage = "Wordlist file not found in the following path: {0}" -f $_
                    $FileNotFoundException = [System.IO.FileNotFoundException]::new($fileNotFoundExceptionMessage)
                    throw $FileNotFoundException
                }
                return $true
            })][System.IO.FileInfo]$WordListFilePath

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

        $wordList = [System.IO.File]::ReadAllLines($WordListFilePath)

        [int]$wordCount = $wordList.Count
        [int]$currentIndex = 1
        [bool]$secretDiscovered = $false

        [string]$outputMessage = "Secret not found."

        foreach ($secret in $wordList) {
            if ($secret.Trim().Length -ge 1) {
                $verboseMessage = "Tested $currentIndex of $wordCount secrets."
                $currentIndex++
                Write-Verbose -Message $verboseMessage

                [bool]$cracked = Test-JwtSignature -JsonWebToken $JsonWebToken -Key $secret.Trim() -HashAlgorithm $HashAlgorithm
                if ($cracked) {
                    $outputMessage = "The following value is the correct token signing key: {0}" -f $secret
                    Write-Output -InputObject $outputMessage
                    $secretDiscovered = $true
                    break
                }
            }
        }

        if (-not($secretDiscovered)) {
            Write-Output -InputObject $outputMessage
        }
    }
}

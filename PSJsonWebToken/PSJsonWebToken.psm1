using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Collections.Generic
using namespace System.Security.Cryptography
using namespace System.Security.Cryptography.X509Certificates

<#
.SYNOPSIS
    Provides functions that create and validate JSON Web Tokens as well as JSON Web Keys.
.DESCRIPTION
    Provides functions that create and validate JSON Web Tokens as well as JSON Web Keys per the following RFCs:

    https://tools.ietf.org/html/rfc7519
    https://tools.ietf.org/html/rfc7517
#>


#region Load classes

Get-ChildItem -Path $PSScriptRoot\ClassDefinitions\*.cs | Foreach-Object {
    Add-Type -Path $_.FullName -ErrorAction Stop
}

#endregion


#region Load Private Functions

Get-ChildItem -Path $PSScriptRoot\PrivateFunctions\*.ps1 | Foreach-Object { . $_.FullName }

#endregion


#region Load Public Functions

Get-ChildItem -Path $PSScriptRoot\Functions\*.ps1 | Foreach-Object { . $_.FullName }

#endregion
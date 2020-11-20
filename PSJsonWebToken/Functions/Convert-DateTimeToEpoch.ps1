function Convert-DateTimeToEpoch
{
    <#
    .SYNOPSIS
        Converts a System.DateTime to an epoch (unix) time stamp.
    .EXAMPLE
        Convert-DateTimeToEpoch

        Returns the current datetime as epoch.
    .EXAMPLE
        $iat = Convert-DateTimeToEpoch
        $nbf = (Get-Date).AddMinutes(-3) | Convert-DateTimeToEpoch
        $exp = (Get-Date).AddMinutes(10) | Convert-DateTimeToEpoch

        $jwtPayload = @{sub="username@domain.com";iat=$iat;nbf=$nbf;exp=$exp}

        $jwtPayloadSerializedAndEncoded = $jwtPayload | ConvertTo-JwtPart

        Generates JWT payload with an iat claim of the current datetime, an nbf claim skewed three minutes in the past, and an expiration of ten minutes in the future from the current datetime.
    .PARAMETER DateTime
        A System.DateTime. Default value is current date and time.
    .INPUTS
        System.DateTime
    .OUTPUTS
        System.Int64
    .LINK
        https://en.wikipedia.org/wiki/Unix_time
        ConvertTo-JwtPart
    #>
    [CmdletBinding()]
    [Alias('GetEpoch')]
    [OutputType([System.Int64])]
    Param
    (
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   Position=0)][ValidateNotNullOrEmpty()][Alias("Date")][DateTime]$DateTime=(Get-Date)
    )

    PROCESS
    {
        $dtut = $DateTime.ToUniversalTime()

        [TimeSpan]$ts = New-TimeSpan -Start  (Get-Date "01/01/1970") -End $dtut

        [Int64]$secondsSinceEpoch = [Math]::Floor($ts.TotalSeconds)

        return $secondsSinceEpoch
    }
}
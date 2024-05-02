function Convert-EpochToDateTime
{
     <#
        .SYNOPSIS
            Converts an epoch (Unix) time stamp to System.DateTime.
        .EXAMPLE
            $jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDI2MDMzMDgsIm5iZiI6MTYwMjYwMzAwOCwiZXhwIjoxNjAyNjAzNjA4LCJzdWIiOiJ0b255Lmd1aW1lbGxpQGdtYWlsLmNvbSJ9.nivxCVSg8MtejEndn31natXPZcdjPHrIvV9_NUeXVtU"

            $deserializedPayload = $jwt | Get-JsonWebTokenPayload

            Convert-EpochToDateTime -Epoch $deserializedPayload.nbf
            Convert-EpochToDateTime -Epoch $deserializedPayload.iat
            Convert-EpochToDateTime -Epoch $deserializedPayload.exp

            Converts the epoch times in a deserialized JWT payload into DateTime objects.
        .PARAMETER Epoch
            The date/time expressed as Unix timestamp.
        .INPUTS
            System.Int
        .OUTPUTS
            System.DateTime
        .LINK
            https://en.wikipedia.org/wiki/Unix_time
            Get-JsonWebTokenPayload
            Convert-DateTimeToEpoch
    #>
    [CmdletBinding()]
    [OutputType([System.DateTime])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipeline=$true,
                   Position=0)][Int]$Epoch
    )
    PROCESS
    {
        [nullable[datetime]]$convertedDateTime = $null
        try
        {
            $dt = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
            $convertedDateTime = $dt.AddSeconds($Epoch)
        }
        catch
        {
            Write-Error -Exception ([ArgumentException]::new("Unable to convert incoming value to DateTime.")) -Category InvalidArgument -ErrorAction Stop
        }

        return $convertedDateTime
    }
}

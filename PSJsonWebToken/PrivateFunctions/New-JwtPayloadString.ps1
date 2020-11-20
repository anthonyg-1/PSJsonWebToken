function New-JwtPayloadString
{
    [CmdletBinding()]
    [OutputType([System.String])]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)][HashTable]$Claims,

        [Parameter(Mandatory=$false,Position=1)]
        [ValidateRange(1,300)]
        [System.Int32]$NotBeforeSkew
    )
    PROCESS
    {
        [string]$payload = ""

        $_claims = [ordered]@{}

        $now = Get-Date
        $currentEpochTime = Convert-DateTimeToEpoch -DateTime $now

        $notBefore = $currentEpochTime
        if ($PSBoundParameters.ContainsKey("NotBeforeSkew"))
        {
            $notBefore = Convert-DateTimeToEpoch -DateTime ($now.AddSeconds(-$NotBeforeSkew))
        }

        $futureEpochTime = Convert-DateTimeToEpoch -DateTime ($now.AddSeconds($TimeToLive))

        $_claims.Add("iat", $currentEpochTime)
        $_claims.Add("nbf", $notBefore)
        $_claims.Add("exp", $futureEpochTime)

        foreach ($entry in $Claims.GetEnumerator())
        {
            if (-not($_claims.Contains($entry.Key)))
            {
                $_claims.Add($entry.Key, $entry.Value)
            }
        }

        $payload = $_claims | ConvertTo-JwtPart

        return $payload
    }
}
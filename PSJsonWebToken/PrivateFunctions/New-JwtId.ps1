function New-JwtId
{
    $guidString = (New-Guid).ToString().Replace("-", "")
    return $guidString
}
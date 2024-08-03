$result = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625; StartTime=(get-date).AddHours(-12)} | ForEach-Object {
    $eventXml = ([xml]$_.ToXml()).Event
    [PsCustomObject]@{
        UserName  = ($eventXml.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        IpAddress = ($eventXml.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        EventDate = [DateTime]$eventXml.System.TimeCreated.SystemTime
    }
}
$result
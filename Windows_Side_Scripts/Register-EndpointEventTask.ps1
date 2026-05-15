param(
    [Parameter(Mandatory=$true)][string]$CollectorUrl,
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [string]$EsetLogDir = "C:\Eset_logs",
    [string]$DailyAt = "23:00",
    [int]$LookbackHours = 24,
    [int]$MaxSecurityEvents = 1500,
    [int]$MaxEventsPerChannel = 1000,
    [int]$MaxEsetRowsPerFile = 2000
)

$TaskName = "SendEndpointEventsToNetworkThesisCollector"
try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}

$argument = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", ('"' + $ScriptPath + '"'),
    "-CollectorUrl", ('"' + $CollectorUrl + '"'),
    "-Token", ('"' + $Token + '"'),
    "-LookbackHours", $LookbackHours,
    "-EsetLogDir", ('"' + $EsetLogDir + '"'),
    "-MaxSecurityEvents", $MaxSecurityEvents,
    "-MaxEventsPerChannel", $MaxEventsPerChannel,
    "-MaxEsetRowsPerFile", $MaxEsetRowsPerFile
) -join " "

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument
$Trigger = New-ScheduledTaskTrigger -Daily -At $DailyAt

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -RunLevel Highest -Description "Sends Windows and ESET endpoint logs to Network Thesis collector" | Out-Null

Write-Host "Task Scheduler task created: $TaskName"
Write-Host "Run time: daily $DailyAt"
Write-Host "Collector URL: $CollectorUrl"
Write-Host "ESET directory: $EsetLogDir"
Write-Host "Manual test:"
Write-Host "  Start-ScheduledTask -TaskName `"$TaskName`""

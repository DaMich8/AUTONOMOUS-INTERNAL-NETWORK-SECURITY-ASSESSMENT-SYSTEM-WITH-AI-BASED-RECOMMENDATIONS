param(
    [Parameter(Mandatory=$true)]
    [string]$CollectorUrl,

    [Parameter(Mandatory=$true)]
    [string]$Token,

    [Parameter(Mandatory=$false)]
    [string]$ScriptPath = "C:\Scripts\Send-SecurityEvents1d.ps1",

    [Parameter(Mandatory=$false)]
    [string]$TaskName = "SendSecurityEventsToNetworkThesisCollector",

    [Parameter(Mandatory=$false)]
    [string]$DailyAt = "03:00",

    [Parameter(Mandatory=$false)]
    [int]$LookbackHours = 24,

    [Parameter(Mandatory=$false)]
    [int]$MaxEvents = 5000
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ScriptPath)) {
    throw "Nerastas siuntimo skriptas: $ScriptPath. Nukopijuok Send-SecurityEvents1d.ps1 į šią vietą arba nurodyk -ScriptPath."
}

$argument = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -CollectorUrl `"$CollectorUrl`" -Token `"$Token`" -LookbackHours $LookbackHours -MaxEvents $MaxEvents"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argument
$trigger = New-ScheduledTaskTrigger -Daily -At $DailyAt
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Sends last 24h Windows Security events to Network Thesis collector"

Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

Write-Host "Task Scheduler užduotis sukurta: $TaskName"
Write-Host "Paleidimo laikas: kasdien $DailyAt"
Write-Host "Collector URL: $CollectorUrl"
Write-Host "Rankinis testas:"
Write-Host "  Start-ScheduledTask -TaskName `"$TaskName`""

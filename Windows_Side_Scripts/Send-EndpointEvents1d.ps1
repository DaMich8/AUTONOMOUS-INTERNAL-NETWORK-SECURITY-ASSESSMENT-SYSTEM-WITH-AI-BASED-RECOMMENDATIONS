param(
    [Parameter(Mandatory=$true)][string]$CollectorUrl,
    [Parameter(Mandatory=$true)][string]$Token,
    [int]$LookbackHours = 24,
    [string]$EsetLogDir = "C:\Eset_logs",
    [int]$MaxSecurityEvents = 1500,
    [int]$MaxEventsPerChannel = 1000,
    [int]$MaxEsetRowsPerFile = 2000,
    [switch]$IncludeAllSecurity,
    [switch]$IncludeMessage,
    [switch]$SkipSecurity,
    [switch]$NoGzip,
    [string]$PayloadOutDir = ""
)

$ErrorActionPreference = "Stop"
$Since = (Get-Date).AddHours(-1 * $LookbackHours)
$Computer = $env:COMPUTERNAME
$SentAt = (Get-Date).ToString("o")

function JsonValue {
    param([object]$Value)
    return ($Value | ConvertTo-Json -Compress -Depth 8)
}

function Get-StringHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hash = $sha.ComputeHash($bytes)
    return -join ($hash | ForEach-Object { $_.ToString("x2") })
}

function Test-EventLogEnabled {
    param([string]$LogName)
    try {
        $out = & wevtutil gl $LogName 2>$null
        if ($LASTEXITCODE -ne 0) { return $false }
        foreach ($line in $out) {
            if ($line -match '^enabled:\s*(true|false)') {
                return ($Matches[1] -eq 'true')
            }
        }
        return $true
    } catch {
        return $false
    }
}

function Convert-EventToSmallObject {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event, [string]$LogName)

    $props = @()
    try {
        foreach ($p in $Event.Properties) {
            if ($null -eq $p.Value) { $props += $null } else { $props += [string]$p.Value }
        }
    } catch { }

    $msg = $null
    if ($IncludeMessage) {
        try { $msg = $Event.FormatDescription() } catch { $msg = $null }
    }

    return [ordered]@{
        source_type = "windows_event"
        computer = $Computer
        log_name = $LogName
        provider = $Event.ProviderName
        event_id = $Event.Id
        level = $Event.Level
        level_display = $Event.LevelDisplayName
        time_created = if ($Event.TimeCreated) { $Event.TimeCreated.ToString("o") } else { $null }
        record_id = $Event.RecordId
        machine_name = $Event.MachineName
        process_id = $Event.ProcessId
        thread_id = $Event.ThreadId
        task = $Event.Task
        opcode = $Event.Opcode
        keywords = [string]$Event.Keywords
        properties = $props
        message = $msg
    }
}

function Write-EventChannelToJsonArray {
    param(
        [System.IO.StreamWriter]$Writer,
        [string]$LogName,
        [int[]]$Ids,
        [int]$MaxEvents,
        [ref]$FirstItem,
        [ref]$TotalCount
    )

    Write-Host "[READ] $LogName"
    if (-not (Test-EventLogEnabled -LogName $LogName)) {
        Write-Host "[SKIP] Log disabled: $LogName"
        return
    }

    try {
        $filter = @{ LogName = $LogName; StartTime = $Since }
        if ($Ids -and $Ids.Count -gt 0) { $filter.Id = $Ids }
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
        $count = 0
        foreach ($ev in $events) {
            $obj = Convert-EventToSmallObject -Event $ev -LogName $LogName
            $json = JsonValue $obj
            if (-not $FirstItem.Value) { $Writer.Write(",") }
            $Writer.Write($json)
            $FirstItem.Value = $false
            $count++
            $TotalCount.Value++
        }
        Write-Host "[OK] $LogName events: $count"
    } catch {
        Write-Host "[WARN] Could not read $LogName : $($_.Exception.Message)"
    }
}

function Write-EsetCsvRowsToJsonArray {
    param(
        [System.IO.StreamWriter]$Writer,
        [ref]$FirstRow,
        [ref]$RowsCount,
        [ref]$FileSummaries
    )

    if (-not (Test-Path $EsetLogDir)) {
        Write-Host "[SKIP] ESET CSV directory not found: $EsetLogDir"
        return
    }

    $files = @(Get-ChildItem -Path $EsetLogDir -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $Since })
    Write-Host "[READ] ESET CSV files changed since $($Since.ToString('s')) -> $($files.Count)"

    foreach ($file in $files) {
        Write-Host "[ESET] Reading file: $($file.FullName)"
        try {
            $lines = @(Get-Content -Path $file.FullName -Tail ($MaxEsetRowsPerFile + 1) -Encoding UTF8 -ErrorAction Stop)
            if ($lines.Count -eq 0) { continue }
            $header = [string]$lines[0]
            $dataLines = @($lines | Select-Object -Skip 1)
            $rowNo = 0
            foreach ($line in $dataLines) {
                $rowNo++
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $obj = [ordered]@{
                    source_type = "eset_csv_row"
                    computer = $Computer
                    filename = $file.Name
                    full_path = $file.FullName
                    file_last_write_time = $file.LastWriteTime.ToString("o")
                    header_line = $header
                    row_number_from_tail = $rowNo
                    row_hash = Get-StringHash -Text ($file.Name + "|" + $line)
                    raw_line = [string]$line
                }
                $json = JsonValue $obj
                if (-not $FirstRow.Value) { $Writer.Write(",") }
                $Writer.Write($json)
                $FirstRow.Value = $false
                $RowsCount.Value++
            }

            $FileSummaries.Value += [ordered]@{
                source_type = "eset_csv_file_summary"
                computer = $Computer
                filename = $file.Name
                full_path = $file.FullName
                size_bytes = $file.Length
                last_write_time = $file.LastWriteTime.ToString("o")
                rows_sent_from_tail = $dataLines.Count
                max_rows_per_file = $MaxEsetRowsPerFile
            }
        } catch {
            $FileSummaries.Value += [ordered]@{
                source_type = "eset_csv_file_error"
                computer = $Computer
                filename = $file.Name
                full_path = $file.FullName
                error = $_.Exception.Message
            }
        }
    }
}

function Write-ObjectListToJsonArray {
    param(
        [System.IO.StreamWriter]$Writer,
        [object[]]$Items
    )
    $first = $true
    foreach ($item in $Items) {
        if (-not $first) { $Writer.Write(",") }
        $Writer.Write((JsonValue $item))
        $first = $false
    }
}

function Compress-FileGzip {
    param([string]$InputPath, [string]$OutputPath)
    $input = [System.IO.File]::OpenRead($InputPath)
    $output = [System.IO.File]::Create($OutputPath)
    try {
        $gzip = New-Object System.IO.Compression.GzipStream($output, [System.IO.Compression.CompressionMode]::Compress)
        try { $input.CopyTo($gzip) } finally { $gzip.Dispose() }
    } finally {
        $input.Dispose()
        $output.Dispose()
    }
}

function Send-FileHttpPost {
    param(
        [string]$Url,
        [string]$FilePath,
        [string]$TokenValue,
        [bool]$Gzip,
        [int64]$UncompressedLength
    )
    $fileInfo = Get-Item $FilePath
    $request = [System.Net.HttpWebRequest]::Create($Url)
    $request.Method = "POST"
    $request.ContentType = "application/json"
    $request.Headers.Add("X-Collector-Token", $TokenValue)
    if ($Gzip) {
        $request.Headers.Add("Content-Encoding", "gzip")
        $request.Headers.Add("X-Uncompressed-Length", [string]$UncompressedLength)
        $request.Headers.Add("X-Compressed-Length", [string]$fileInfo.Length)
    }
    $request.ContentLength = $fileInfo.Length
    $request.Timeout = 180000
    $request.ReadWriteTimeout = 180000

    $reqStream = $request.GetRequestStream()
    $fs = [System.IO.File]::OpenRead($FilePath)
    try {
        $buffer = New-Object byte[] 65536
        while (($read = $fs.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $reqStream.Write($buffer, 0, $read)
        }
    } finally {
        $fs.Dispose()
        $reqStream.Dispose()
    }

    try {
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        try { return $reader.ReadToEnd() } finally { $reader.Dispose(); $response.Dispose() }
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $body = $reader.ReadToEnd()
            $reader.Dispose()
            throw "HTTP error: $($_.Exception.Message). Receiver response: $body"
        }
        throw
    }
}

# Important IDs. IncludeAllSecurity can override Security filter.
$SecurityIds = @(1102,4624,4625,4634,4647,4648,4672,4688,4697,4720,4722,4723,4724,4725,4726,4732,4733,4738,4740,4768,4769,4771,4776)
$SystemIds = @(6005,6006,6008,7000,7001,7009,7011,7031,7034,7040,7045)
$WindowsPowerShellIds = @(400,403,600,800)
$PowerShellOperationalIds = @(4103,4104,4105,4106)
$RdpLocalIds = @(21,22,23,24,25,39,40)
$RdpRemoteIds = @(1149,261)
$TaskSchedulerIds = @(106,140,141,200,201)
$WmiIds = @(5857,5858,5859,5860,5861)

if ([string]::IsNullOrWhiteSpace($PayloadOutDir)) {
    $PayloadOutDir = Join-Path $env:TEMP "network_thesis_endpoint_payload"
}
New-Item -ItemType Directory -Force -Path $PayloadOutDir | Out-Null
$stamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $PayloadOutDir "$($Computer)_$($stamp)_endpoint_payload.json"
$gzPath = "$jsonPath.gz"

$eventCount = 0
$esetRowsCount = 0
$esetFilesCount = 0

Write-Host "[BUILD] Streaming JSON directly to file: $jsonPath"
$writer = New-Object System.IO.StreamWriter($jsonPath, $false, [System.Text.Encoding]::UTF8)
try {
    $writer.Write("{")
    $writer.Write('"payload_type":'); $writer.Write((JsonValue "endpoint_events_with_eset_csv_rows")); $writer.Write(",")
    $writer.Write('"schema_version":'); $writer.Write((JsonValue "2.6-gzip-streaming")); $writer.Write(",")
    $writer.Write('"computer":'); $writer.Write((JsonValue $Computer)); $writer.Write(",")
    $writer.Write('"sent_at":'); $writer.Write((JsonValue $SentAt)); $writer.Write(",")
    $writer.Write('"lookback_hours":'); $writer.Write($LookbackHours); $writer.Write(",")
    $writer.Write('"max_events_per_channel":'); $writer.Write($MaxEventsPerChannel); $writer.Write(",")
    $writer.Write('"max_security_events":'); $writer.Write($MaxSecurityEvents); $writer.Write(",")
    $writer.Write('"max_eset_rows_per_file":'); $writer.Write($MaxEsetRowsPerFile); $writer.Write(",")
    $writer.Write('"include_all_security":'); if ($IncludeAllSecurity) { $writer.Write("true") } else { $writer.Write("false") }; $writer.Write(",")
    $writer.Write('"include_message":'); if ($IncludeMessage) { $writer.Write("true") } else { $writer.Write("false") }; $writer.Write(",")

    $writer.Write('"events":[')
    $firstEvent = $true
    if (-not $SkipSecurity) {
        if ($IncludeAllSecurity) {
            Write-EventChannelToJsonArray -Writer $writer -LogName "Security" -Ids @() -MaxEvents $MaxSecurityEvents -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
        } else {
            Write-EventChannelToJsonArray -Writer $writer -LogName "Security" -Ids $SecurityIds -MaxEvents $MaxSecurityEvents -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
        }
    } else { Write-Host "[SKIP] Security" }
    Write-EventChannelToJsonArray -Writer $writer -LogName "System" -Ids $SystemIds -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    Write-EventChannelToJsonArray -Writer $writer -LogName "Application" -Ids @() -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    Write-EventChannelToJsonArray -Writer $writer -LogName "Windows PowerShell" -Ids $WindowsPowerShellIds -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    Write-EventChannelToJsonArray -Writer $writer -LogName "Microsoft-Windows-PowerShell/Operational" -Ids $PowerShellOperationalIds -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    Write-EventChannelToJsonArray -Writer $writer -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" -Ids @() -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    Write-EventChannelToJsonArray -Writer $writer -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -Ids $RdpLocalIds -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    Write-EventChannelToJsonArray -Writer $writer -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -Ids $RdpRemoteIds -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    Write-EventChannelToJsonArray -Writer $writer -LogName "Microsoft-Windows-TaskScheduler/Operational" -Ids $TaskSchedulerIds -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    Write-EventChannelToJsonArray -Writer $writer -LogName "Microsoft-Windows-WMI-Activity/Operational" -Ids $WmiIds -MaxEvents $MaxEventsPerChannel -FirstItem ([ref]$firstEvent) -TotalCount ([ref]$eventCount)
    $writer.Write("],")

    $writer.Write('"eset_csv_rows":[')
    $firstRow = $true
    $esetFileSummaries = @()
    Write-EsetCsvRowsToJsonArray -Writer $writer -FirstRow ([ref]$firstRow) -RowsCount ([ref]$esetRowsCount) -FileSummaries ([ref]$esetFileSummaries)
    $esetFilesCount = $esetFileSummaries.Count
    $writer.Write("],")

    $writer.Write('"eset_csv_files":[')
    Write-ObjectListToJsonArray -Writer $writer -Items $esetFileSummaries
    $writer.Write("],")

    $metadata = [ordered]@{
        user = $env:USERNAME
        os = [System.Environment]::OSVersion.VersionString
        powershell_version = $PSVersionTable.PSVersion.ToString()
    }
    $writer.Write('"metadata":'); $writer.Write((JsonValue $metadata)); $writer.Write(",")
    $stats = [ordered]@{
        windows_events_count = $eventCount
        eset_csv_rows_count = $esetRowsCount
        eset_csv_files_count = $esetFilesCount
    }
    $writer.Write('"stats":'); $writer.Write((JsonValue $stats))
    $writer.Write("}")
} finally {
    $writer.Dispose()
}

$jsonSize = (Get-Item $jsonPath).Length
Write-Host "[BUILD] JSON file bytes: $jsonSize"

$sendPath = $jsonPath
$gzipUsed = $false
if (-not $NoGzip) {
    Write-Host "[BUILD] Compressing file with gzip"
    Compress-FileGzip -InputPath $jsonPath -OutputPath $gzPath
    $sendPath = $gzPath
    $gzipUsed = $true
    Write-Host "[BUILD] Gzip file bytes: $((Get-Item $gzPath).Length)"
}

$sendSize = (Get-Item $sendPath).Length
$ratio = if ($jsonSize -gt 0) { [math]::Round(($sendSize / $jsonSize) * 100, 2) } else { 100 }
Write-Host "[SEND] windows_events=$eventCount eset_rows=$esetRowsCount eset_files=$esetFilesCount json_bytes=$jsonSize send_bytes=$sendSize gzip=$gzipUsed ratio=$ratio%"
Write-Host "[SEND] POST $CollectorUrl"
$responseText = Send-FileHttpPost -Url $CollectorUrl -FilePath $sendPath -TokenValue $Token -Gzip $gzipUsed -UncompressedLength $jsonSize
Write-Host "[OK] Response: $responseText"

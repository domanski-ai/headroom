[CmdletBinding()]
param(
    [string]$BaseUrl = "http://127.0.0.1:8377",
    [string]$DashboardUrl = "http://127.0.0.1:8377/"
)

# EXPERIMENTAL: PowerShell 5.1 tray client. It reads the display-only widget
# contract and uses only bundled icon files.
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:Tray = New-Object System.Windows.Forms.NotifyIcon
$script:Context = New-Object System.Windows.Forms.ApplicationContext
$script:CurrentIcon = $null
$IconRoot = Join-Path $PSScriptRoot "icons"
$IconFiles = @{
    green = Join-Path $IconRoot "headroom-green.ico"
    amber = Join-Path $IconRoot "headroom-amber.ico"
    red = Join-Path $IconRoot "headroom-red.ico"
    gray = Join-Path $IconRoot "headroom-gray.ico"
}

function Set-TrayStatus {
    param(
        [ValidateSet("green", "amber", "red", "gray")][string]$State,
        [string]$Tooltip
    )
    if (-not (Test-Path -LiteralPath $IconFiles[$State] -PathType Leaf)) {
        $State = "gray"
        $Tooltip = "headroom OFFLINE"
    }
    $nextIcon = New-Object System.Drawing.Icon($IconFiles[$State])
    $previousIcon = $script:CurrentIcon
    $script:CurrentIcon = $nextIcon
    $script:Tray.Icon = $nextIcon
    if ($null -ne $previousIcon) { $previousIcon.Dispose() }
    if ([String]::IsNullOrEmpty($Tooltip)) { $Tooltip = "headroom OFFLINE" }
    $script:Tray.Text = $Tooltip.Substring(0, [Math]::Min(63, $Tooltip.Length))
    $script:Tray.Visible = $true
}

function Refresh-Headroom {
    try {
        $uri = $BaseUrl.TrimEnd("/") + "/widget.json"
        $response = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 3
        if ([Text.Encoding]::UTF8.GetByteCount($response.Content) -gt 65536) {
            throw "widget response too large"
        }
        $data = $response.Content | ConvertFrom-Json
        if ($data.schema -ne "headroom_widget@1") { throw "widget schema mismatch" }
        if ($null -eq $data.freshness -or $data.freshness.state -ne "current") {
            throw "widget is not current"
        }
        $now = [Math]::Floor(([DateTimeOffset]::UtcNow -
                [DateTimeOffset]"1970-01-01T00:00:00Z").TotalSeconds)
        $evaluatedAt = [double]$data.freshness.evaluated_at
        $ageSeconds = [double]$data.freshness.age_seconds
        if ($evaluatedAt -gt $now -or ($now - $evaluatedAt) -gt 300 -or
                $ageSeconds -lt 0 -or $ageSeconds -gt 900) {
            throw "widget clock invalid"
        }
        if ($null -eq $data.accounts -or $null -eq $data.headline) {
            throw "widget fields missing"
        }
        $current = [int]$data.headline.current_accounts
        $total = [int]$data.headline.total_accounts
        $accountCount = @($data.accounts).Count
        if ($current -lt 0 -or $total -lt $current -or
                $total -ne $accountCount) { throw "widget counts invalid" }
        $fullest = $data.headline.fullest_5h_left_percent
        if ($null -eq $fullest) {
            Set-TrayStatus "gray" ("headroom: {0}/{1} current, fullest --" -f
                                    $current, $total)
            return
        }
        $percent = [double]$fullest
        if ([Double]::IsNaN($percent) -or [Double]::IsInfinity($percent) -or
                $percent -lt 0 -or $percent -gt 100) {
            throw "widget percentage invalid"
        }
        if ($percent -gt 50) { $state = "green" }
        elseif ($percent -gt 10) { $state = "amber" }
        else { $state = "red" }
        Set-TrayStatus $state ("headroom: {0}/{1} current, fullest {2}%" -f
                               $current, $total, [Math]::Round($percent))
    }
    catch {
        Set-TrayStatus "gray" "headroom OFFLINE"
    }
}

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$refreshItem = New-Object System.Windows.Forms.ToolStripMenuItem("Refresh")
$refreshItem.add_Click({ Refresh-Headroom })
[void]$menu.Items.Add($refreshItem)
$openItem = New-Object System.Windows.Forms.ToolStripMenuItem("Open dashboard")
$openItem.add_Click({ Start-Process $DashboardUrl })
[void]$menu.Items.Add($openItem)
$exitItem = New-Object System.Windows.Forms.ToolStripMenuItem("Exit")
$exitItem.add_Click({
    $script:Timer.Stop()
    $script:Tray.Visible = $false
    $script:Context.ExitThread()
})
[void]$menu.Items.Add($exitItem)
$script:Tray.ContextMenuStrip = $menu

$script:Timer = New-Object System.Windows.Forms.Timer
$script:Timer.Interval = 60000
$script:Timer.add_Tick({ Refresh-Headroom })

Set-TrayStatus "gray" "headroom OFFLINE"
Refresh-Headroom
$script:Timer.Start()
[System.Windows.Forms.Application]::Run($script:Context)

$script:Timer.Dispose()
$script:Tray.Dispose()
if ($null -ne $script:CurrentIcon) { $script:CurrentIcon.Dispose() }

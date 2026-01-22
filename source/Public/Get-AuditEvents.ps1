function Get-AuditEvents {
    <#
    .SYNOPSIS
    Function to generate a report of device activity. Primarily startup and shutdown times, user logon/logoff times and lock/unlock times.
    .DESCRIPTION
    Function retrieves several types of events from Event Logs to build a timeline of useful activity. By correlating start, shutdown, logon, logoff, lock and unlock events
    we can build a picture of what type of activity is related to the user.
    .PARAMETER ComputerName
    If provided will attempt to connect to a remote computer to retrieve logs using Get-WinEvent.
    .PARAMETER Timeframe
    By default will retrieve events from 1 day ago through now. Can use the Timeframe parameter to specify that the function should retrieve all matching events.
    .EXAMPLE
    PS> Get-AuditEvents

    .NOTES
        Version:    1.0
        Author:     C. Bodett
        Creation Date: 1/21/2026
        Purpose/Change: initial module development
    #>
    [Cmdletbinding()]
    param (
        [string]$ComputerName = $ENV:COMPUTERNAME,
        [ValidateSet('All','Day')]
        [string]$Timeframe = "Day"
    )

    switch ($TimeFrame) {
        "Day" {$Days = -1}
        "All" {$Days = -365}
    }

    $StartTime = ((Get-Date -Hour 0 -Minute 0 -Second 0).ToUniversalTime().AddDays($Days) | Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")

    $FilterXML = @"
<QueryList>
<Query Id="0" Path="System">
    <Select Path="System">
    *[System[TimeCreated[@SystemTime >= '$StartTime']]]
    and
    *[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=12]]
    </Select>
    <Select Path="System">
    *[System[TimeCreated[@SystemTime >= '$StartTime']]]
    and
    *[System[(EventID=1074)]]
    </Select>
    <Select Path="Security">
        *[System[TimeCreated[@SystemTime >= '$StartTime']]]
        and
        *[System[(EventID=4624)]
        and
        EventData[Data[@Name='LogonType'] and (Data='2' or Data='11' or Data='10')]
        and
        EventData[Data[@Name='ProcessName'] = 'C:\Windows\System32\svchost.exe']
        ]
    </Select>
    <Select Path="Security">
        *[System[TimeCreated[@SystemTime >= '$StartTime']]]
        and
        *[System[(EventID=4647)]]
    </Select>
    <Select Path="Security">
        *[System[TimeCreated[@SystemTime >= '$StartTime']]]
        and
        *[System[(EventID=4800 or EventID=4801)]]
    </Select>
</Query>
</QueryList>
"@

    $EventLogs = try {
        Get-WinEvent -ComputerName $ComputerName -FilterXml $FilterXML -ErrorAction Stop
    } catch {
        throw $_
    }

    $EventObjs = foreach ($EventLog in $EventLogs) {
        $Xml = [xml]$EventLog.ToXml()
        $DataTable = @{}
        foreach ($Data in $Xml.Event.EventData.Data) {
            $DataTable[$Data.Name] = $Data.'#text'
        }
        $EventLogProperties = [PSCustomObject]$DataTable
        switch ($EventLog.Id) {
            12 {# Operating System startup
                $EventName = "Computer Started"
                $EventDetails = 'Started at:{0}' -f (Get-Date $EventLogProperties.StartTime)
                $LogonId = $null
            }
            1074 {# System Shutdown
                $EventName = "Computer Shutdown"
                $EventDetails = 'Process:{0}, User:{1}, App:{2}, Comment:{3}' -f $EventLogProperties.param1, $EventLogProperties.param7, $EventLogProperties.param3, $EventLogProperties.param6
                $LogonId = $null
            }
            4800 {# Workstation locked
                $EventName = "Workstation Locked"
                $EventDetails = 'User:{0}' -f $EventLogProperties.TargetUserName
                $LogonId = $EventLogProperties.TargetLogonId
            }
            4801 {# Workstation unlocked
                $EventName = "Workstation Unlocked"
                $EventDetails = 'User:{0}' -f $EventLogProperties.TargetUserName
                $LogonId = $EventLogProperties.TargetLogonId
            }
            4624 {# User logged on
                $EventName = "User Logged On"
                $LogonType = switch ($EventLogProperties.LogonType) {
                    2 {"Interactive"}
                    11 {"CachedInteractive"}
                    10 {"RemoteDesktop"}
                }
                $EventDetails = 'User:{0}, LogonType:{1}' -f $EventLogProperties.TargetUserName, $LogonType
                $LogonId = $EventLogProperties.TargetLogonId
            }
            4647 {# User logged off
                $EventName = "User Logged Off"
                $EventDetails = 'User:{0}' -f $EventLogProperties.TargetUserName
                $LogonId = $EventLogProperties.TargetLogonId
            }
        }

        [PSCustomObject]@{
            PSTypeName = "AuditEvent"
            Time = $EventLog.TimeCreated
            EventId = $EventLog.Id
            Event = $EventName
            LogonId = $LogonId
            Details = $EventDetails
        }
    }

    # Add lock duration to lock events
    foreach ($LockEvent in ($EventObjs | Where-Object {$_.EventId -match "4800|4801"} | Sort-Object Time)) {
        if ($LockEvent.EventId -eq "4800") {
            # Computer Locked
            $StartLock = $LockEvent.Time
        } elseif ($LockEvent.EventId -eq "4801") {
            if ($StartLock) {
                $TimeSpan = New-TimeSpan -Start $StartLock -End $LockEvent.Time
                $LockEvent.Details += ', TimeSinceLock:{0:hh\:mm\:ss}' -f $Timespan
                $StartLock = $null
            } else {
                $LockEvent.Details += ', TimeSinceLock:NotFound'
            }
        }
    }

    # Add uptime to shutdown events
    foreach ($PowerEvent in ($EventObjs | Where-Object {$_.EventId -match "^12|1074$"} | Sort-Object Time)) {
        if ($PowerEvent.EventId -eq "12") {
            # Computer Started
            $Startup = $PowerEvent.Time
        } elseif ($PowerEvent.EventId -eq "1074") {
            if ($Startup) {
                $TimeSpan = New-TimeSpan -Start $Startup -End $PowerEvent.Time
                $PowerEvent.Details += ', TimeSinceBoot:{0:hh\:mm\:ss}' -f $Timespan
                $Startup = $null
            } else {
                $PowerEvent.Details += ', TimeSinceBoot:NotFound'
            }
        }
    }

    $EventObjs
}
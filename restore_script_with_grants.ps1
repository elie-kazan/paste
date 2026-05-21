<#
.SYNOPSIS
    Self-service TSM/DP SQL restore. Snapshots target grants, then creates a
    two-step SQL Agent job that runs Restore-DpSqlBackup (step 1) and replays
    the grants snapshot (step 2). Wrapper exits as soon as the job is started.

.DESCRIPTION
    No polling, no wait. Restore can run for tens of hours; user closes the
    window and uses their own query to track progress. Step 2 auto-runs after
    step 1 succeeds; on step 1 failure, step 2 is skipped and the job ends
    in failure.

.EXAMPLE
    .\Run-Restore.ps1 -FromSqlServer "CS9PRDB03398\DX_SV_RS6ETAFIDR" `
                      -SourceDatabase "TGK_DATA_017" `
                      -SqlServer "CS9VADB03134\DP_SV_RS6ETAFIDR,12001" `
                      -RestoreDate "02/27/2026" -RestoreTime "17:00:00" `
                      -TsmOptFile "C:\Program Files\Tivoli\TSM\TDPSql\ISPPROXY-CS9VADB03134-CS9PRDB03398-SQL.opt"
#>

[CmdletBinding()]
param(
    [string]$FromSqlServer,
    [string]$SourceDatabase,
    [string]$SqlServer,
    [string]$RestoreDate,
    [string]$RestoreTime,
    [string]$TsmOptFile,

    [string]$ConfigFile  = "C:\Program Files\Tivoli\TSM\TDPSql\tdpsql.cfg",
    [string]$QueryNode   = "DP",
    [string]$GrantsDir   = "C:\Scripts\SQL\Grants",
    [string]$LogDir      = "C:\Logs\TSM-Restore",
    [bool]  $IncludeHashedPasswords = $true
)

Import-Module SqlServer -ErrorAction Stop

# =====================================================================
# Helpers
# =====================================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Write-Host $line
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line }
}

# ---------------------------------------------------------------------
# Get-DefaultDataPath
# ---------------------------------------------------------------------
function Get-DefaultDataPath {
    param([string]$SqlInstance)
    try {
        $row = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
            SELECT SERVERPROPERTY('InstanceDefaultDataPath') AS DataPath" -ErrorAction Stop
        if ($row.DataPath) { return ($row.DataPath -replace '\\$','') }

        $row = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
            SELECT TOP 1 physical_name FROM sys.master_files
            WHERE database_id = 1 AND type = 0" -ErrorAction Stop
        return (Split-Path $row.physical_name -Parent)
    } catch {
        Write-Log "Could not detect default data path: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# ---------------------------------------------------------------------
# Export-DbGrants
# ---------------------------------------------------------------------
function Export-DbGrants {
    param(
        [string]$SqlInstance,
        [string]$Database,
        [string]$OutputDir,
        [bool]$IncludeHashedPasswords
    )

    try {
        $exists = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
            SELECT 1 AS x FROM sys.databases WHERE name = '$Database'" -ErrorAction Stop
    } catch {
        Write-Log "Cannot query target instance: $($_.Exception.Message)" "ERROR"
        return $null
    }

    if (-not $exists) {
        Write-Log "Target DB [$Database] does not exist yet — no grants to snapshot." "WARN"
        return $null
    }

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $safe   = ($SqlInstance -replace '[\\,:]','_') + "_${Database}"
    $stamp  = Get-Date -Format "yyyyMMdd-HHmmss"
    $outFile = Join-Path $OutputDir "grants_${safe}_${stamp}.sql"

    Write-Log "Snapshotting grants from [$SqlInstance].[$Database] -> $outFile"

    if ($IncludeHashedPasswords) {
        $sqlLoginClause = @"
            'CREATE LOGIN ' + QUOTENAME(sp.name) +
            ' WITH PASSWORD = 0x' +
            CONVERT(VARCHAR(MAX), sl.password_hash, 2) + ' HASHED, SID = 0x' +
            CONVERT(VARCHAR(MAX), sp.sid, 2) + ', ' +
            'CHECK_POLICY = ' + CASE WHEN sl.is_policy_checked = 1 THEN 'ON' ELSE 'OFF' END + ', ' +
            'DEFAULT_DATABASE = ' + QUOTENAME(ISNULL(sp.default_database_name,'master')) + ';'
"@
    } else {
        $sqlLoginClause = @"
            'CREATE LOGIN ' + QUOTENAME(sp.name) +
            ' WITH PASSWORD = ''CHANGE_ME_' + sp.name + ''' MUST_CHANGE, ' +
            'CHECK_POLICY = ON, ' +
            'DEFAULT_DATABASE = ' + QUOTENAME(ISNULL(sp.default_database_name,'master')) + ';'
"@
    }

    $loginsQuery = @"
SET NOCOUNT ON;
SELECT
    'IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = ''' + sp.name + ''') ' +
    CASE sp.type
        WHEN 'S' THEN
$sqlLoginClause
        ELSE
            'CREATE LOGIN ' + QUOTENAME(sp.name) + ' FROM WINDOWS ' +
            'WITH DEFAULT_DATABASE = ' + QUOTENAME(ISNULL(sp.default_database_name,'master')) + ';'
    END AS stmt
FROM sys.server_principals sp
INNER JOIN [$Database].sys.database_principals dp ON dp.sid = sp.sid
LEFT JOIN sys.sql_logins sl ON sl.sid = sp.sid
WHERE sp.type IN ('S','U','G')
  AND sp.name NOT LIKE '##%'
  AND sp.name NOT IN ('sa');
"@

    $usersQuery = @"
SET NOCOUNT ON;
USE [$Database];
SELECT
    'IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = ''' + dp.name COLLATE DATABASE_DEFAULT + ''') ' +
    'CREATE USER ' + QUOTENAME(dp.name) COLLATE DATABASE_DEFAULT +
    CASE WHEN sp.name IS NOT NULL THEN ' FOR LOGIN ' + QUOTENAME(sp.name) COLLATE DATABASE_DEFAULT ELSE ' WITHOUT LOGIN' END +
    ' WITH DEFAULT_SCHEMA = ' + QUOTENAME(ISNULL(dp.default_schema_name,'dbo')) COLLATE DATABASE_DEFAULT + ';' AS stmt
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON sp.sid = dp.sid
WHERE dp.type IN ('S','U','G')
  AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys');
"@

    $rolesQuery = @"
SET NOCOUNT ON;
USE [$Database];
SELECT
    'ALTER ROLE ' + QUOTENAME(r.name) COLLATE DATABASE_DEFAULT + ' ADD MEMBER ' + QUOTENAME(m.name) COLLATE DATABASE_DEFAULT + ';' AS stmt
FROM sys.database_role_members rm
JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id
WHERE m.name NOT IN ('dbo');
"@

    $permsQuery = @"
SET NOCOUNT ON;
USE [$Database];
SELECT
    CASE dp.state WHEN 'G' THEN 'GRANT ' WHEN 'W' THEN 'GRANT '
                  WHEN 'D' THEN 'DENY '  WHEN 'R' THEN 'REVOKE ' END +
    dp.permission_name COLLATE DATABASE_DEFAULT +
    CASE
        WHEN dp.class = 0 THEN ''
        WHEN dp.class = 1 THEN ' ON ' + QUOTENAME(SCHEMA_NAME(o.schema_id)) COLLATE DATABASE_DEFAULT + '.' + QUOTENAME(o.name) COLLATE DATABASE_DEFAULT
        WHEN dp.class = 3 THEN ' ON SCHEMA::' + QUOTENAME(s.name) COLLATE DATABASE_DEFAULT
        ELSE ''
    END +
    ' TO ' + QUOTENAME(USER_NAME(dp.grantee_principal_id)) COLLATE DATABASE_DEFAULT +
    CASE WHEN dp.state = 'W' THEN ' WITH GRANT OPTION' ELSE '' END + ';' AS stmt
FROM sys.database_permissions dp
LEFT JOIN sys.objects o ON dp.class = 1 AND dp.major_id = o.object_id
LEFT JOIN sys.schemas s ON dp.class = 3 AND dp.major_id = s.schema_id
WHERE USER_NAME(dp.grantee_principal_id) NOT IN ('public','dbo','guest','INFORMATION_SCHEMA','sys');
"@

    $logins = (Invoke-Sqlcmd -ServerInstance $SqlInstance -Database master    -Query $loginsQuery -ErrorAction Stop).stmt
    $users  = (Invoke-Sqlcmd -ServerInstance $SqlInstance -Database $Database -Query $usersQuery  -ErrorAction Stop).stmt
    $roles  = (Invoke-Sqlcmd -ServerInstance $SqlInstance -Database $Database -Query $rolesQuery  -ErrorAction Stop).stmt
    $perms  = (Invoke-Sqlcmd -ServerInstance $SqlInstance -Database $Database -Query $permsQuery  -ErrorAction Stop).stmt

    $header = @"
-- =====================================================================
-- Grants snapshot for [$Database] on [$SqlInstance]
-- Captured : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
-- By       : $env:USERNAME
-- Hashed pw: $IncludeHashedPasswords
-- =====================================================================
SET NOCOUNT ON;
GO

"@

    $body  = @()
    $body += "-- ===== 1. Server logins (run in master) ====="
    $body += "USE [master];"; $body += "GO"
    if ($logins) { $body += $logins } else { $body += "-- (none)" }
    $body += "GO"
    $body += ""
    $body += "-- ===== 2. Database users ====="
    $body += "USE [$Database];"; $body += "GO"
    if ($users) { $body += $users } else { $body += "-- (none)" }
    $body += "GO"
    $body += ""
    $body += "-- ===== 3. Role memberships ====="
    if ($roles) { $body += $roles } else { $body += "-- (none)" }
    $body += "GO"
    $body += ""
    $body += "-- ===== 4. Permissions ====="
    if ($perms) { $body += $perms } else { $body += "-- (none)" }
    $body += "GO"

    ($header + ($body -join "`r`n")) | Out-File -FilePath $outFile -Encoding UTF8

    Write-Log ("Snapshot complete: logins={0}, users={1}, roles={2}, perms={3}" -f `
        @($logins).Count, @($users).Count, @($roles).Count, @($perms).Count)
    return $outFile
}

# ---------------------------------------------------------------------
# Start-RestoreJob
#   Creates a two-step Agent job (restore + grants) and starts it.
#   Returns the job name. No polling, no wait.
# ---------------------------------------------------------------------
function Start-RestoreJob {
    param(
        [string]$FromSqlServer,
        [string]$SourceDb,
        [string]$SqlServer,
        [string]$IntoDbName,
        [string]$RestoreDate,
        [string]$RestoreTime,
        [string]$TsmOptFile,
        [string]$ConfigFile,
        [string]$QueryNode,
        [string]$RelocateDir,
        [string]$GrantsFile,
        [string]$StepLogDir
    )

    $jobName   = "RestoreJob_${SourceDb}_$(Get-Date -Format 'yyyyMMddHHmmss')_$env:USERNAME"
    $dpLogFile = Join-Path $StepLogDir "${jobName}_dpsql.txt"

    Write-Log "Job name        : $jobName"
    Write-Log "DP LogFile      : $dpLogFile"
    Write-Log "RelocateDir     : $RelocateDir"
    Write-Log "Grants snapshot : $GrantsFile"

    # ----- Step 1 command: Restore-DpSqlBackup -----
    $step1Ps = @"
Import-Module SqlServer;
Restore-DpSqlBackup ``
    -Name              ''$SourceDb'' ``
    -BackupDestination TSM ``
    -BackupMethod      legacy ``
    -Replace ``
    -SqlServer         ''$SqlServer'' ``
    -SQLAUTHentication INTegrated ``
    -Stripes           1 ``
    -FromSqlServer     ''$FromSqlServer'' ``
    -QueryNode         ''$QueryNode'' ``
    -IntoDBName        ''$IntoDbName'' ``
    -RestoreDate       ''$RestoreDate'' ``
    -RestoreTime       ''$RestoreTime'' ``
    -MountWait         Yes ``
    -RelocateDir       ''$RelocateDir'' ``
    -ConfigFile        ''$ConfigFile'' ``
    -TsmOptFile        ''$TsmOptFile'' ``
    -LogFile           ''$dpLogFile'';
"@

    # ----- Step 2 command: replay grants -----
    # Skip gracefully if no snapshot was generated (first-time restore)
    if ($GrantsFile) {
        $step2Ps = @"
if (Test-Path ''$GrantsFile'') {
    Import-Module SqlServer;
    Invoke-Sqlcmd -ServerInstance ''$SqlServer'' -Database ''$IntoDbName'' -InputFile ''$GrantsFile'' -ErrorAction Stop;
    Write-Output ''Grants replayed from $GrantsFile'';
} else {
    Write-Output ''No grants snapshot file found; skipping.'';
}
"@
    } else {
        $step2Ps = "Write-Output 'No grants snapshot was taken (target DB did not exist); skipping replay.';"
    }

    $step1Cmd = $step1Ps -replace "'", "''"
    $step2Cmd = $step2Ps -replace "'", "''"

    $createJobSql = @"
USE msdb;
DECLARE @jobId UNIQUEIDENTIFIER;

EXEC dbo.sp_add_job
    @job_name    = N'$jobName',
    @enabled     = 1,
    @description = N'TSM restore + grants replay, by $env:USERNAME',
    @job_id      = @jobId OUTPUT;

EXEC dbo.sp_add_jobserver @job_id = @jobId, @server_name = N'(LOCAL)';

-- Step 1: Restore
EXEC dbo.sp_add_jobstep
    @job_id            = @jobId,
    @step_id           = 1,
    @step_name         = N'1 - Restore-DpSqlBackup',
    @subsystem         = N'PowerShell',
    @command           = N'$step1Cmd',
    @on_success_action = 3,    -- go to next step
    @on_fail_action    = 2,    -- quit reporting failure
    @output_file_name  = N'$StepLogDir\${jobName}_step1.log';

-- Step 2: Grants replay
EXEC dbo.sp_add_jobstep
    @job_id            = @jobId,
    @step_id           = 2,
    @step_name         = N'2 - Replay grants',
    @subsystem         = N'PowerShell',
    @command           = N'$step2Cmd',
    @on_success_action = 1,    -- quit reporting success
    @on_fail_action    = 2,    -- quit reporting failure
    @output_file_name  = N'$StepLogDir\${jobName}_step2.log';

EXEC dbo.sp_update_job @job_id = @jobId, @start_step_id = 1;
EXEC dbo.sp_start_job  @job_name = N'$jobName';
"@

    Invoke-Sqlcmd -ServerInstance $SqlServer -Query $createJobSql -ErrorAction Stop
    Write-Log "Two-step job created and started. Returning control."
    return $jobName
}

# =====================================================================
# Main
# =====================================================================
Write-Host "=== Self-Service SQL Restore from TSM ===" -ForegroundColor Cyan

if (-not $FromSqlServer)  { $FromSqlServer  = Read-Host "Source SQL instance (FromSqlServer)" }
if (-not $SourceDatabase) { $SourceDatabase = Read-Host "Source database name" }
if (-not $SqlServer)      { $SqlServer      = Read-Host "Target SQL instance (with ,port if needed)" }
if (-not $RestoreDate)    { $RestoreDate    = Read-Host "Restore date (MM/DD/YYYY)" }
if (-not $RestoreTime)    { $RestoreTime    = Read-Host "Restore time (HH:MM:SS)" }
if (-not $TsmOptFile)     { $TsmOptFile     = Read-Host "Full path to TSM .opt file" }

$IntoDbName = $SourceDatabase  # overwrite mode

if (-not (Test-Path $LogDir))    { New-Item -ItemType Directory -Path $LogDir    -Force | Out-Null }
if (-not (Test-Path $GrantsDir)) { New-Item -ItemType Directory -Path $GrantsDir -Force | Out-Null }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$script:LogFile = Join-Path $LogDir "restore_${SourceDatabase}_${stamp}_$env:USERNAME.log"

Write-Log "User        : $env:USERNAME"
Write-Log "From        : $FromSqlServer / $SourceDatabase"
Write-Log "Into        : $SqlServer / $IntoDbName (overwrite)"
Write-Log "RestoreDate : $RestoreDate $RestoreTime"
Write-Log "TsmOptFile  : $TsmOptFile"
Write-Log "ConfigFile  : $ConfigFile"
Write-Log "LogFile     : $script:LogFile"

foreach ($f in @($TsmOptFile, $ConfigFile)) {
    if (-not (Test-Path $f)) {
        Write-Log "Required file not found: $f" "FATAL"
        exit 1
    }
}

$RelocateDir = Get-DefaultDataPath -SqlInstance $SqlServer
if (-not $RelocateDir) {
    Write-Log "Could not detect target default data path — aborting." "FATAL"
    exit 1
}
Write-Log "Target default data path: $RelocateDir"

# 1. Snapshot target grants
$grantsFile = Export-DbGrants -SqlInstance $SqlServer `
                              -Database    $IntoDbName `
                              -OutputDir   $GrantsDir `
                              -IncludeHashedPasswords $IncludeHashedPasswords

# 2. Kick connections off the existing DB
try {
    Invoke-Sqlcmd -ServerInstance $SqlServer -Query "
        IF DB_ID('$IntoDbName') IS NOT NULL
        BEGIN
            ALTER DATABASE [$IntoDbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
            ALTER DATABASE [$IntoDbName] SET MULTI_USER;
        END" -ErrorAction Stop
    Write-Log "Cleared connections to [$IntoDbName]"
} catch {
    Write-Log "Pre-restore connection clear: $($_.Exception.Message)" "WARN"
}

# 3. Create + start the two-step job; exit immediately after
$jobName = Start-RestoreJob `
    -FromSqlServer $FromSqlServer `
    -SourceDb      $SourceDatabase `
    -SqlServer     $SqlServer `
    -IntoDbName    $IntoDbName `
    -RestoreDate   $RestoreDate `
    -RestoreTime   $RestoreTime `
    -TsmOptFile    $TsmOptFile `
    -ConfigFile    $ConfigFile `
    -QueryNode     $QueryNode `
    -RelocateDir   $RelocateDir `
    -GrantsFile    $grantsFile `
    -StepLogDir    $LogDir

Write-Log "=== Job dispatched: $jobName ==="
Write-Host ""
Write-Host "Job '$jobName' is running on $SqlServer." -ForegroundColor Green
Write-Host "Use your usual progress query to track it." -ForegroundColor Green
Write-Host "Grants snapshot: $grantsFile" -ForegroundColor Green

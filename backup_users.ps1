<#
.SYNOPSIS
    Extract logins, users, role memberships, and permissions from a SQL Server
    database into a replayable .sql script.

.PARAMETER SqlInstance
    Target SQL Server instance (e.g. "SRV02", "SRV02\INST1", "localhost").

.PARAMETER Database
    Database name to extract grants from.

.PARAMETER OutputDir
    Directory where the .sql file will be written. Created if missing.
    Default: current directory.

.PARAMETER OutputFile
    Explicit output file path. Overrides OutputDir if given.

.PARAMETER IncludeHashedPasswords
    Include SQL login password hashes so logins replay with real passwords.
    Requires VIEW SERVER STATE permission. Without this switch, SQL logins get
    placeholder passwords.

.PARAMETER Force
    Overwrite output file if it exists.

.EXAMPLE
    .\Export-DbGrants.ps1 -SqlInstance "localhost" -Database "MYDB"

.EXAMPLE
    .\Export-DbGrants.ps1 -SqlInstance "SRV02\INST1" -Database "MYDB" `
                          -OutputDir "C:\Scripts\Grants" -IncludeHashedPasswords

.EXAMPLE
    .\Export-DbGrants.ps1 -SqlInstance "." -Database "MYDB" `
                          -OutputFile "C:\temp\mydb_grants.sql" -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SqlInstance,

    [Parameter(Mandatory)]
    [string]$Database,

    [string]$OutputDir = (Get-Location).Path,

    [string]$OutputFile,

    [switch]$IncludeHashedPasswords,

    [switch]$Force
)

# ---------- prereq ----------
if (-not (Get-Module -ListAvailable SqlServer)) {
    Write-Error "SqlServer PowerShell module not found. Run: Install-Module SqlServer"
    exit 1
}
Import-Module SqlServer -ErrorAction Stop

# ---------- resolve output path ----------
if (-not $OutputFile) {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    $safe   = ($SqlInstance -replace '\\','_') + "_${Database}"
    $stamp  = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputFile = Join-Path $OutputDir "grants_${safe}_${stamp}.sql"
}

if ((Test-Path $OutputFile) -and -not $Force) {
    Write-Error "Output file already exists: $OutputFile. Use -Force to overwrite."
    exit 1
}

Write-Host "Source     : [$SqlInstance].[$Database]" -ForegroundColor Cyan
Write-Host "Output     : $OutputFile" -ForegroundColor Cyan
Write-Host "Hashed pwd : $IncludeHashedPasswords" -ForegroundColor Cyan
Write-Host ""

# ---------- verify DB exists ----------
try {
    $check = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
        SELECT name FROM sys.databases WHERE name = '$Database'" -ErrorAction Stop
} catch {
    Write-Error "Cannot connect to [$SqlInstance]: $($_.Exception.Message)"
    exit 1
}
if (-not $check) {
    Write-Error "Database [$Database] not found on [$SqlInstance]."
    exit 1
}

# ---------- 1. Server logins referenced by this DB ----------
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

# ---------- 2. Database users ----------
$usersQuery = @"
SET NOCOUNT ON;
USE [$Database];
SELECT
    'IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = ''' + dp.name + ''') ' +
    'CREATE USER ' + QUOTENAME(dp.name) +
    CASE WHEN sp.name IS NOT NULL THEN ' FOR LOGIN ' + QUOTENAME(sp.name) ELSE ' WITHOUT LOGIN' END +
    ' WITH DEFAULT_SCHEMA = ' + QUOTENAME(ISNULL(dp.default_schema_name,'dbo')) + ';' AS stmt
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON sp.sid = dp.sid
WHERE dp.type IN ('S','U','G')
  AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys');
"@

# ---------- 3. Role memberships ----------
$rolesQuery = @"
SET NOCOUNT ON;
USE [$Database];
SELECT
    'ALTER ROLE ' + QUOTENAME(r.name) + ' ADD MEMBER ' + QUOTENAME(m.name) + ';' AS stmt
FROM sys.database_role_members rm
JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id
WHERE m.name NOT IN ('dbo');
"@

# ---------- 4. Permissions ----------
$permsQuery = @"
SET NOCOUNT ON;
USE [$Database];
SELECT
    CASE dp.state WHEN 'G' THEN 'GRANT ' WHEN 'W' THEN 'GRANT '
                  WHEN 'D' THEN 'DENY '  WHEN 'R' THEN 'REVOKE ' END +
    dp.permission_name +
    CASE
        WHEN dp.class = 0 THEN ''
        WHEN dp.class = 1 THEN ' ON ' + QUOTENAME(SCHEMA_NAME(o.schema_id)) + '.' + QUOTENAME(o.name)
        WHEN dp.class = 3 THEN ' ON SCHEMA::' + QUOTENAME(s.name)
        ELSE ''
    END +
    ' TO ' + QUOTENAME(USER_NAME(dp.grantee_principal_id)) +
    CASE WHEN dp.state = 'W' THEN ' WITH GRANT OPTION' ELSE '' END + ';' AS stmt
FROM sys.database_permissions dp
LEFT JOIN sys.objects o ON dp.class = 1 AND dp.major_id = o.object_id
LEFT JOIN sys.schemas s ON dp.class = 3 AND dp.major_id = s.schema_id
WHERE USER_NAME(dp.grantee_principal_id) NOT IN ('public','dbo','guest','INFORMATION_SCHEMA','sys');
"@

# ---------- run queries ----------
Write-Host "Querying logins..."
$logins = (Invoke-Sqlcmd -ServerInstance $SqlInstance -Database master    -Query $loginsQuery -ErrorAction Stop).stmt
Write-Host "Querying users..."
$users  = (Invoke-Sqlcmd -ServerInstance $SqlInstance -Database $Database -Query $usersQuery -ErrorAction Stop).stmt
Write-Host "Querying role memberships..."
$roles  = (Invoke-Sqlcmd -ServerInstance $SqlInstance -Database $Database -Query $rolesQuery -ErrorAction Stop).stmt
Write-Host "Querying permissions..."
$perms  = (Invoke-Sqlcmd -ServerInstance $SqlInstance -Database $Database -Query $permsQuery -ErrorAction Stop).stmt

# ---------- assemble ----------
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

($header + ($body -join "`r`n")) | Out-File -FilePath $OutputFile -Encoding UTF8

# ---------- summary ----------
$counts = @{
    Logins = if ($logins) { @($logins).Count } else { 0 }
    Users  = if ($users)  { @($users).Count }  else { 0 }
    Roles  = if ($roles)  { @($roles).Count }  else { 0 }
    Perms  = if ($perms)  { @($perms).Count }  else { 0 }
}

Write-Host ""
Write-Host "=== Export complete ===" -ForegroundColor Green
Write-Host ("  Logins      : {0}" -f $counts.Logins)
Write-Host ("  DB users    : {0}" -f $counts.Users)
Write-Host ("  Role members: {0}" -f $counts.Roles)
Write-Host ("  Permissions : {0}" -f $counts.Perms)
Write-Host ""
Write-Host "Output: $OutputFile" -ForegroundColor Cyan

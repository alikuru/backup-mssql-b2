#Requires -Version 5.1
<#
.SYNOPSIS
    Automated SQL Server database backup script with compression, rotation, and cloud synchronization.
    
.DESCRIPTION
    This script performs the following operations:
    1. Backs up all or specified SQL Server databases
    2. Compresses backups using 7-Zip
    3. Rotates backups based on configured retention period
    4. Synchronizes backups to Backblaze B2
    5. Sends email notification of success or failure
    
.NOTES
    File Name      : Backup-SQLServer.ps1
    Author         : 
    Prerequisite   : 
    - PowerShell 5.1 or later
    - SQL Server instance
    - 7-Zip installed
    - Backblaze B2 CLI installed
    - SMTP server access
#>

# Script Parameters
param (
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = ".\config.json"
)

#region Functions

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with appropriate color
    switch ($Level) {
        "INFO"    { Write-Host $logMessage -ForegroundColor White }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
}

function Read-Config {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ConfigPath
    )
    
    try {
        if (-not (Test-Path $ConfigPath)) {
            throw "Configuration file not found at path: $ConfigPath"
        }
        
        $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
        
        # Validate required configuration properties
        $requiredProps = @(
            "SQLServer",
            "BackupPath",
            "RetentionDays",
            "Compression",
            "BackblazeB2"
        )
        
        foreach ($prop in $requiredProps) {
            if (-not $config.PSObject.Properties.Name.Contains($prop)) {
                throw "Required configuration property missing: $prop"
            }
        }
        
        return $config
    }
    catch {
        Write-Log "Failed to read configuration: $_" -Level "ERROR"
        exit 1
    }
}

function Load-SqlServerAssemblies {
    Write-Log "Attempting to load SQL Server assemblies..."
    
    # Try multiple methods to load the assemblies
    $loaded = $false
    
    # Method 1: Try to import the SqlServer module (preferred for newer environments)
    try {
        Import-Module SqlServer -ErrorAction Stop
        Write-Log "Successfully loaded SqlServer module"
        $loaded = $true
        return $true
    }
    catch {
        Write-Log "Could not load SqlServer module: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Method 2: Try to import the SQLPS module (older environments)
    if (-not $loaded) {
        try {
            Import-Module SQLPS -DisableNameChecking -ErrorAction Stop
            Write-Log "Successfully loaded SQLPS module"
            $loaded = $true
            return $true
        }
        catch {
            Write-Log "Could not load SQLPS module: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Method 3: Try to load the assemblies directly with specific versions
    if (-not $loaded) {
        try {
            # SQL Server 2017/2019 assemblies
            Add-Type -AssemblyName "Microsoft.SqlServer.Smo, Version=14.0.0.0, Culture=neutral, PublicKeyToken=89845dcd8080cc91" -ErrorAction Stop
            Add-Type -AssemblyName "Microsoft.SqlServer.SmoExtended, Version=14.0.0.0, Culture=neutral, PublicKeyToken=89845dcd8080cc91" -ErrorAction Stop
            Write-Log "Successfully loaded SQL Server 2017/2019 SMO assemblies"
            $loaded = $true
            return $true
        }
        catch {
            Write-Log "Could not load SQL Server 2017/2019 SMO assemblies: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Method 4: Try to load the assemblies directly with other versions
    if (-not $loaded) {
        $versions = @("16.0.0.0", "15.0.0.0", "14.0.0.0", "13.0.0.0", "12.0.0.0", "11.0.0.0", "10.0.0.0")
        foreach ($version in $versions) {
            try {
                Add-Type -AssemblyName "Microsoft.SqlServer.Smo, Version=$version, Culture=neutral, PublicKeyToken=89845dcd8080cc91" -ErrorAction Stop
                Add-Type -AssemblyName "Microsoft.SqlServer.SmoExtended, Version=$version, Culture=neutral, PublicKeyToken=89845dcd8080cc91" -ErrorAction Stop
                Write-Log "Successfully loaded SQL Server SMO assemblies version $version"
                $loaded = $true
                return $true
            }
            catch {
                Write-Log "Could not load SQL Server SMO assemblies version $version" -Level "WARNING"
            }
        }
    }
    
    # Method 5: Try to find and load the assemblies from common installation paths
    if (-not $loaded) {
        $sqlServerPaths = @(
            "C:\Program Files\Microsoft SQL Server",
            "C:\Program Files (x86)\Microsoft SQL Server"
        )
        
        foreach ($basePath in $sqlServerPaths) {
            if (Test-Path $basePath) {
                $smoPath = Get-ChildItem -Path $basePath -Recurse -Filter "Microsoft.SqlServer.Smo.dll" -ErrorAction SilentlyContinue | 
                           Where-Object { $_.FullName -match "SDK\\Assemblies" } | 
                           Select-Object -First 1 -ExpandProperty FullName
                
                if ($smoPath) {
                    try {
                        Add-Type -Path $smoPath -ErrorAction Stop
                        Write-Log "Successfully loaded SMO assembly from path: $smoPath"
                        $loaded = $true
                        return $true
                    }
                    catch {
                        Write-Log "Could not load SMO assembly from path $($smoPath): $($_.Exception.Message)" -Level "WARNING"
                    }
                }
            }
        }
    }
    
    # Method 6: Last resort - try LoadWithPartialName
    if (-not $loaded) {
        try {
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
            [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
            
            # Verify the assemblies were loaded
            $smoAssembly = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -like "*Microsoft.SqlServer.Smo*" }
            
            if ($smoAssembly) {
                Write-Log "Successfully loaded SQL Server SMO assemblies using LoadWithPartialName"
                $loaded = $true
                return $true
            }
            else {
                Write-Log "LoadWithPartialName did not successfully load the SMO assemblies" -Level "WARNING"
            }
        }
        catch {
            Write-Log "Could not load SQL Server SMO assemblies using LoadWithPartialName: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    if (-not $loaded) {
        Write-Log "Failed to load SQL Server SMO assemblies using any method" -Level "ERROR"
        return $false
    }
}

function Backup-Databases {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    
    try {
        # Load SQL Server assemblies
        if (-not (Load-SqlServerAssemblies)) {
            throw "Failed to load SQL Server assemblies"
        }
        
        # Create backup directory if it doesn't exist
        if (-not (Test-Path $Config.BackupPath)) {
            New-Item -Path $Config.BackupPath -ItemType Directory -Force | Out-Null
            Write-Log "Created backup directory: $($Config.BackupPath)"
        }
        
        # Create timestamp for backup folder
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFolder = Join-Path -Path $Config.BackupPath -ChildPath $timestamp
        New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
        Write-Log "Created backup folder for this run: $backupFolder"
        
        # Connect to SQL Server
        try {
            $sqlServer = $Config.SQLServer.ServerInstance
            $sqlCredential = $null
            
            # Use SQL authentication if credentials are provided
            if ($Config.SQLServer.UseIntegratedSecurity -ne $true) {
                $sqlUsername = $Config.SQLServer.Username
                $sqlPassword = $Config.SQLServer.Password
                
                if ([string]::IsNullOrEmpty($sqlUsername) -or [string]::IsNullOrEmpty($sqlPassword)) {
                    throw "SQL authentication credentials are required when not using integrated security"
                }
                
                $securePassword = ConvertTo-SecureString $sqlPassword -AsPlainText -Force
                $sqlCredential = New-Object System.Management.Automation.PSCredential($sqlUsername, $securePassword)
            }
            
            # Create SQL Server connection
            $server = New-Object Microsoft.SqlServer.Management.Smo.Server $sqlServer
            
            if ($sqlCredential) {
                $server.ConnectionContext.LoginSecure = $false
                $server.ConnectionContext.Login = $sqlUsername
                $server.ConnectionContext.Password = $sqlPassword
            }
            
            Write-Log "Connected to SQL Server: $sqlServer"
            
            # Get databases to backup
            $databasesToBackup = @()
            
            if ($Config.SQLServer.Databases -and $Config.SQLServer.Databases.Count -gt 0) {
                # Backup specific databases
                foreach ($dbName in $Config.SQLServer.Databases) {
                    $db = $server.Databases[$dbName]
                    if ($db) {
                        $databasesToBackup += $db
                    }
                    else {
                        Write-Log "Database not found: $dbName" -Level "WARNING"
                    }
                }
            }
            else {
                # Backup all user databases
                $databasesToBackup = $server.Databases | Where-Object { -not $_.IsSystemObject }
            }
            
            Write-Log "Found $($databasesToBackup.Count) databases to backup"
            
            # Backup each database
            $backupFiles = @()
            $databaseDetails = @()
            $successCount = 0
            $failureCount = 0
            $failedDatabases = @()
            
            foreach ($database in $databasesToBackup) {
                $dbName = $database.Name
                $backupFile = Join-Path -Path $backupFolder -ChildPath "$dbName.bak"
                
                Write-Log "Starting backup of database: $dbName"
                
                try {
                    $backup = New-Object Microsoft.SqlServer.Management.Smo.Backup
                    $backup.Action = [Microsoft.SqlServer.Management.Smo.BackupActionType]::Database
                    $backup.BackupSetDescription = "Full backup of $dbName"
                    $backup.BackupSetName = "$dbName backup"
                    $backup.Database = $dbName
                    $backup.MediaDescription = "Disk"
                    $backup.Devices.AddDevice($backupFile, [Microsoft.SqlServer.Management.Smo.DeviceType]::File)
                    $backup.Initialize = $true
                    
                    # Execute the backup
                    $startTime = Get-Date
                    $backup.SqlBackup($server)
                    $endTime = Get-Date
                    $duration = $endTime - $startTime
                    
                    # Get file size
                    $fileInfo = Get-Item $backupFile
                    $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
                    
                    $databaseDetails += @{
                        Name = $dbName
                        Status = "Success"
                        FilePath = $backupFile
                        SizeMB = $fileSizeMB
                        Duration = $duration
                        StartTime = $startTime
                        EndTime = $endTime
                    }
                    
                    Write-Log "Completed backup of database: $dbName to $backupFile"
                    $backupFiles += $backupFile
                    $successCount++
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    Write-Log "Failed to backup database $($dbName): $($errorMsg)" -Level "ERROR"
                    
                    $databaseDetails += @{
                        Name = $dbName
                        Status = "Failed"
                        Error = $errorMsg
                    }
                    
                    $failureCount++
                    $failedDatabases += $dbName
                }
            }
            
            return @{
                "BackupFolder" = $backupFolder
                "BackupFiles" = $backupFiles
                "DatabaseDetails" = $databaseDetails
                "TotalDatabases" = $databasesToBackup.Count
                "SuccessCount" = $successCount
                "FailureCount" = $failureCount
                "FailedDatabases" = $failedDatabases
            }
        }
        catch {
            Write-Log "Failed to connect to SQL Server or perform backup: $_" -Level "ERROR"
            throw $_
        }
    }
    catch {
        Write-Log "Database backup failed: $_" -Level "ERROR"
        throw $_
    }
}

function Compress-Backups {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$true)]
        [string]$BackupFolder,
        
        [Parameter(Mandatory=$true)]
        [array]$DatabaseDetails
    )
    
    try {
        # Check if 7-Zip is available
        $7zipPath = $Config.Compression.Path
        if (-not (Test-Path $7zipPath)) {
            throw "7-Zip executable not found at path: $7zipPath"
        }
        
        # Set compression level
        $compressionLevel = $Config.Compression.Level
        if (-not $compressionLevel) {
            $compressionLevel = 5  # Default compression level
        }
        
        $timestamp = Split-Path -Path $BackupFolder -Leaf
        $compressedFiles = @()
        
        # Compress each database backup individually
        foreach ($db in $DatabaseDetails) {
            if ($db.Status -eq "Success") {
                $dbName = $db.Name
                $backupFile = $db.FilePath
                
                # Create compressed file name with database name and timestamp
                $compressedFileName = "$dbName-$timestamp.7z"
                $compressedFile = Join-Path -Path $Config.BackupPath -ChildPath $compressedFileName
                
                Write-Log "Compressing backup for database $dbName to: $compressedFile"
                
                # Compress the backup file
                $arguments = "a -t7z `"$compressedFile`" `"$backupFile`" -mx=$compressionLevel"
                $process = Start-Process -FilePath $7zipPath -ArgumentList $arguments -NoNewWindow -PassThru -Wait
                
                if ($process.ExitCode -ne 0) {
                    throw "7-Zip compression failed for database $dbName with exit code: $($process.ExitCode)"
                }
                
                Write-Log "Compression completed successfully for database $dbName"
                
                # Update database details with compressed file information
                $db.CompressedFile = $compressedFile
                $db.CompressedSizeMB = [math]::Round((Get-Item $compressedFile).Length / 1MB, 2)
                
                $compressedFiles += $compressedFile
            }
        }
        
        # Remove the original backup folder to save space
        Remove-Item -Path $BackupFolder -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Removed original backup folder after compression"
        
        return $compressedFiles
    }
    catch {
        Write-Log "Compression failed: $_" -Level "ERROR"
        
        # Attempt to clean up the backup folder even if compression fails
        if (Test-Path $BackupFolder) {
            Remove-Item -Path $BackupFolder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Cleaned up backup folder after compression failure" -Level "WARNING"
        }
        
        throw $_
    }
}

function Remove-OldBackups {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    
    try {
        $retentionDays = $Config.RetentionDays
        Write-Log "Removing backup files older than $retentionDays days"
        
        # Get current date
        $currentDate = Get-Date
        
        # Get all backup files
        $backupFiles = Get-ChildItem -Path $Config.BackupPath -Filter "*.7z" -File
        
        # Count of removed files
        $removedCount = 0
        
        # Check each backup file
        foreach ($file in $backupFiles) {
            # Calculate file age in days
            $fileAge = ($currentDate - $file.LastWriteTime).Days
            
            # Remove files older than retention days
            if ($fileAge -gt $retentionDays) {
                Remove-Item -Path $file.FullName -Force
                Write-Log "Removed old backup file: $($file.Name)"
                $removedCount++
            }
        }
        
        Write-Log "Removed $removedCount old backup files"
    }
    catch {
        Write-Log "Error removing old backups: $_" -Level "ERROR"
        throw $_
    }
}

function Remove-OldLogs {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    
    try {
        $retentionDays = $Config.RetentionDays
        Write-Log "Removing log files older than $retentionDays days"
        
        # Get current date
        $currentDate = Get-Date
        
        # Get all log files in the logs directory
        $logFiles = Get-ChildItem -Path $logsPath -Filter "*.log" -File
        
        # Count of removed files
        $removedCount = 0
        
        # Check each log file
        foreach ($file in $logFiles) {
            # Skip the current log file
            if ($file.FullName -eq $script:logFile) {
                continue
            }
            
            # Calculate file age in days
            $fileAge = ($currentDate - $file.LastWriteTime).Days
            
            # Remove files older than retention days
            if ($fileAge -gt $retentionDays) {
                Remove-Item -Path $file.FullName -Force
                Write-Log "Removed old log file: $($file.Name)"
                $removedCount++
            }
        }
        
        if ($removedCount -gt 0) {
            Write-Log "Removed $removedCount old log files"
        }
        else {
            Write-Log "No old log files to remove"
        }
    }
    catch {
        Write-Log "Failed to remove old logs: $_" -Level "WARNING"
        # Continue execution even if cleanup fails
    }
}

function Sync-ToBackblaze {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    
    try {
        $b2Config = $Config.BackblazeB2
        
        # Check if B2 sync is enabled
        if (-not $b2Config.Enabled) {
            Write-Log "Backblaze B2 sync is disabled in configuration"
            return
        }
        
        # Validate B2 configuration
        if ([string]::IsNullOrEmpty($b2Config.KeyId) -or [string]::IsNullOrEmpty($b2Config.ApplicationKey) -or [string]::IsNullOrEmpty($b2Config.BucketName)) {
            throw "Backblaze B2 configuration is incomplete. KeyId, ApplicationKey, and BucketName are required."
        }
        
        Write-Log "Starting Backblaze B2 sync for backup directory"
        
        # Set B2 credentials as environment variables
        $env:B2_APPLICATION_KEY_ID = $b2Config.KeyId
        $env:B2_APPLICATION_KEY = $b2Config.ApplicationKey
        
        # Get the B2 CLI path
        $b2CliPath = $b2Config.CliPath
        if (-not (Test-Path $b2CliPath)) {
            throw "Backblaze B2 CLI not found at path: $b2CliPath"
        }
        
        # Authorize account
        $authorizeArgs = "account authorize"
        $process = Start-Process -FilePath $b2CliPath -ArgumentList $authorizeArgs -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -ne 0) {
            throw "B2 authorization failed with exit code: $($process.ExitCode)"
        }
        
        # Determine source and destination paths
        $sourcePath = $Config.BackupPath
        $destinationPath = "b2://$($b2Config.BucketName)"
        if (-not [string]::IsNullOrEmpty($b2Config.FolderPath)) {
            $destinationPath += "/$($b2Config.FolderPath)"
        }
        
        # Sync the backup directory to B2 with delete flag to remove files that don't exist locally
        Write-Log "Syncing backup directory to Backblaze B2: $sourcePath -> $destinationPath"
        $syncArgs = "sync --delete --no-progress `"$sourcePath`" `"$destinationPath`""
        $process = Start-Process -FilePath $b2CliPath -ArgumentList $syncArgs -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -ne 0) {
            throw "B2 sync failed with exit code: $($process.ExitCode)"
        }
        
        Write-Log "Successfully synchronized backup directory to Backblaze B2"
        
        # Clear environment variables
        $env:B2_APPLICATION_KEY_ID = $null
        $env:B2_APPLICATION_KEY = $null
    }
    catch {
        Write-Log "Backblaze B2 sync failed: $_" -Level "ERROR"
        throw $_
    }
}

function Send-EmailNotification {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$true)]
        [bool]$Success,
        
        [Parameter(Mandatory=$false)]
        [string]$ErrorMessage = "",
        
        [Parameter(Mandatory=$false)]
        [hashtable]$BackupInfo = @{}
    )
    
    try {
        $emailConfig = $Config.Email
        
        # Check if email notifications are enabled
        if (-not $emailConfig.Enabled) {
            Write-Log "Email notifications are disabled in configuration"
            return
        }
        
        # Validate email configuration
        if ([string]::IsNullOrEmpty($emailConfig.SmtpServer) -or [string]::IsNullOrEmpty($emailConfig.From) -or [string]::IsNullOrEmpty($emailConfig.To)) {
            throw "Email configuration is incomplete. SmtpServer, From, and To are required."
        }
        
        Write-Log "Preparing email notification"
        
        # Build email subject
        $subject = if ($Success) {
            if ($BackupInfo.ContainsKey("SuccessCount") -and $BackupInfo.ContainsKey("TotalDatabases")) {
                "SQL Backup Success: $($BackupInfo.SuccessCount)/$($BackupInfo.TotalDatabases) DBs on $($Config.SQLServer.ServerInstance) - $(Get-Date -Format 'yyyy-MM-dd')"
            } else {
                "SQL Server Backup Successful - $($Config.SQLServer.ServerInstance) - $(Get-Date -Format 'yyyy-MM-dd')"
            }
        }
        else {
            if ($BackupInfo.ContainsKey("FailureCount") -and $BackupInfo.ContainsKey("TotalDatabases")) {
                "SQL Backup FAILED: $($BackupInfo.FailureCount)/$($BackupInfo.TotalDatabases) DBs failed on $($Config.SQLServer.ServerInstance) - $(Get-Date -Format 'yyyy-MM-dd')"
            } else {
                "SQL Server Backup FAILED - $($Config.SQLServer.ServerInstance) - $(Get-Date -Format 'yyyy-MM-dd')"
            }
        }
        
        # Build email body
        $body = @"
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .success { color: green; }
        .warning { color: orange; }
        .failure { color: red; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .success-row { background-color: #f0fff0; }
        .failure-row { background-color: #fff0f0; }
    </style>
</head>
<body>
    <h2>SQL Server Backup Report</h2>
    <p>Server: $($Config.SQLServer.ServerInstance)</p>
    <p>Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <h3 class="$(if($Success){'success'}else{'failure'})">
        Overall Status: $(if($Success){'SUCCESS'}else{'FAILURE'})
    </h3>
"@
        
        if ($BackupInfo.ContainsKey("DatabaseDetails") -and $BackupInfo.DatabaseDetails.Count -gt 0) {
            $body += @"
    <h4>Database Backup Details:</h4>
    <table>
        <tr>
            <th>Database</th>
            <th>Status</th>
            <th>Size (Uncompressed)</th>
            <th>Size (Compressed)</th>
            <th>Duration</th>
            <th>Backup File</th>
        </tr>
"@
            
            foreach ($db in $BackupInfo.DatabaseDetails) {
                $rowClass = if ($db.Status -eq "Success") { "success-row" } else { "failure-row" }
                $statusClass = if ($db.Status -eq "Success") { "success" } else { "failure" }
                $sizeInfo = if ($db.Status -eq "Success") { "$($db.SizeMB) MB" } else { "N/A" }
                $compressedSizeInfo = if ($db.Status -eq "Success" -and $db.CompressedSizeMB) { "$($db.CompressedSizeMB) MB" } else { "N/A" }
                $durationInfo = if ($db.Status -eq "Success") { "$([math]::Round($db.Duration.TotalSeconds, 2)) seconds" } else { "N/A" }
                $backupFileInfo = if ($db.Status -eq "Success" -and $db.CompressedFile) { 
                    $fileName = Split-Path -Path $db.CompressedFile -Leaf
                    $fileName
                } else { "N/A" }
                
                $body += @"
        <tr class="$rowClass">
            <td>$($db.Name)</td>
            <td class="$statusClass">$($db.Status)</td>
            <td>$sizeInfo</td>
            <td>$compressedSizeInfo</td>
            <td>$durationInfo</td>
            <td>$backupFileInfo</td>
        </tr>
"@
            }
            
            $body += @"
    </table>
    
    <p>
        <strong>Summary:</strong> 
        Total Databases: $($BackupInfo.TotalDatabases), 
        Successful: <span class="success">$($BackupInfo.SuccessCount)</span>, 
        Failed: <span class="failure">$($BackupInfo.FailureCount)</span>
    </p>
"@
        }
        
        if ($Success -and $Config.BackblazeB2.Enabled) {
            $body += @"
    <p class="success">All backup files were successfully synchronized to Backblaze B2.</p>
"@
        }
        
        if (-not $Success) {
            if ($BackupInfo.ContainsKey("FailedDatabases") -and $BackupInfo.FailedDatabases.Count -gt 0) {
                $body += @"
    <h4>Failed Databases:</h4>
    <ul>
"@
                foreach ($failedDb in $BackupInfo.FailedDatabases) {
                    $body += @"
        <li>$failedDb</li>
"@
                }
                $body += @"
    </ul>
"@
            }
            
            $body += @"
    <h4>Error Details:</h4>
    <pre style="color: red; background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd;">$ErrorMessage</pre>
"@
        }
        
        $body += @"
    <p>This is an automated message. Please do not reply.</p>
</body>
</html>
"@
        
        # Create email parameters
        $emailParams = @{
            SmtpServer = $emailConfig.SmtpServer
            Port = if ($emailConfig.Port) { $emailConfig.Port } else { 25 }
            From = $emailConfig.From
            To = $emailConfig.To -split "," | ForEach-Object { $_.Trim() }
            Subject = $subject
            Body = $body
            BodyAsHtml = $true
        }
        
        # Add credentials if provided
        if (-not [string]::IsNullOrEmpty($emailConfig.Username) -and -not [string]::IsNullOrEmpty($emailConfig.Password)) {
            $securePassword = ConvertTo-SecureString $emailConfig.Password -AsPlainText -Force
            $credential = New-Object System.Management.Automation.PSCredential($emailConfig.Username, $securePassword)
            $emailParams.Add("Credential", $credential)
        }
        
        # Add SSL if enabled
        if ($emailConfig.EnableSsl -eq $true) {
            $emailParams.Add("UseSsl", $true)
        }
        
        # Send the email
        Send-MailMessage @emailParams
        
        Write-Log "Email notification sent successfully"
    }
    catch {
        Write-Log "Failed to send email notification: $_" -Level "WARNING"
        # Continue execution even if email fails
    }
}

function Cleanup-TempDirectories {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$false)]
        [string]$BackupFolder = $null
    )
    
    try {
        Write-Log "Starting cleanup of temporary directories"
        
        # Clean up specific backup folder if provided
        if ($BackupFolder -and (Test-Path $BackupFolder)) {
            Remove-Item -Path $BackupFolder -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed specific backup folder: $BackupFolder"
        }
        
        # Find and clean up any temporary backup folders that might have been left behind
        # These would be folders with timestamp names (yyyyMMdd_HHmmss format)
        if (Test-Path $Config.BackupPath) {
            $tempFolders = Get-ChildItem -Path $Config.BackupPath -Directory | 
                           Where-Object { $_.Name -match '^\d{8}_\d{6}$' }
            
            foreach ($folder in $tempFolders) {
                # Check if folder is older than 1 day (to avoid removing currently running backups)
                if ($folder.LastWriteTime -lt (Get-Date).AddDays(-1)) {
                    Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Removed old temporary backup folder: $($folder.FullName)" -Level "WARNING"
                }
            }
            
            $removedCount = ($tempFolders | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1) }).Count
            if ($removedCount -gt 0) {
                Write-Log "Removed $removedCount old temporary backup folders" -Level "WARNING"
            }
        }
        
        Write-Log "Temporary directory cleanup completed"
    }
    catch {
        Write-Log "Error during temporary directory cleanup: $_" -Level "WARNING"
        # Continue execution even if cleanup fails
    }
}

#endregion

#region Logging Functions

function Start-Log {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    
    try {
        # Create log filename with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "SQLBackup_$timestamp.log"
        $script:logFile = Join-Path -Path $logsPath -ChildPath $logFileName
        
        # Create log file
        $script:logStream = [System.IO.StreamWriter]::new($script:logFile, $true)
        
        # Log script start
        Write-Log "===== SQL Server Backup Script Started at $(Get-Date) ====="
        Write-Log "Log file: $script:logFile"
        
        # Rotate old logs
        Rotate-Logs -RetentionDays $Config.RetentionDays
    }
    catch {
        Write-Host "Error initializing log file: $_" -ForegroundColor Red
        throw $_
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    # Format timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Format log message
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color based on level
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor Gray }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Write to log file if initialized
    if ($script:logStream) {
        $script:logStream.WriteLine($logMessage)
        $script:logStream.Flush()
    }
}

function Stop-Log {
    if ($script:logStream) {
        Write-Log "===== SQL Server Backup Script Completed at $(Get-Date) ====="
        $script:logStream.Close()
        $script:logStream.Dispose()
        $script:logStream = $null
    }
}

function Rotate-Logs {
    param (
        [Parameter(Mandatory=$true)]
        [int]$RetentionDays
    )
    
    try {
        Write-Log "Rotating log files older than $RetentionDays days"
        
        # Get current date
        $currentDate = Get-Date
        
        # Get all log files
        $logFiles = Get-ChildItem -Path $logsPath -Filter "SQLBackup_*.log" -File
        
        # Count of removed files
        $removedCount = 0
        
        # Check each log file
        foreach ($file in $logFiles) {
            # Skip the current log file
            if ($file.FullName -eq $script:logFile) {
                continue
            }
            
            # Calculate file age in days
            $fileAge = ($currentDate - $file.LastWriteTime).Days
            
            # Remove files older than retention days
            if ($fileAge -gt $RetentionDays) {
                Remove-Item -Path $file.FullName -Force
                Write-Log "Removed old log file: $($file.FullName)"
                $removedCount++
            }
        }
        
        if ($removedCount -gt 0) {
            Write-Log "Removed $removedCount old log files"
        }
        else {
            Write-Log "No old log files to remove"
        }
    }
    catch {
        Write-Log "Error rotating log files: $_" -Level "ERROR"
        # Continue execution even if log rotation fails
    }
}

#endregion

#region Main Script Execution

# Initialize script
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path -Path $scriptPath -ChildPath "config.json"

# Create logs directory if it doesn't exist
$logsPath = Join-Path -Path $scriptPath -ChildPath "logs"
if (-not (Test-Path -Path $logsPath)) {
    New-Item -Path $logsPath -ItemType Directory -Force | Out-Null
    Write-Host "Created logs directory: $logsPath"
}

# Global variables
$script:logFile = $null
$script:logStream = $null

# Main execution
try {
    # Read configuration
    $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    
    # Start logging
    Start-Log -Config $config
    
    Write-Log "SQL Server Backup Script started"
    Write-Log "Using configuration file: $configPath"
    Write-Log "Configuration loaded successfully"
    
    # Backup databases
    Write-Log "Starting database backup process"
    $backupResult = Backup-Databases -Config $config
    
    # Compress backups
    Write-Log "Starting backup compression"
    $compressedFiles = Compress-Backups -Config $config -BackupFolder $backupResult.BackupFolder -DatabaseDetails $backupResult.DatabaseDetails
    
    # Remove old backups
    Write-Log "Starting backup rotation"
    Remove-OldBackups -Config $config
    
    # Remove old logs
    Write-Log "Starting log rotation"
    Remove-OldLogs -Config $config
    
    # Sync to Backblaze B2 if enabled
    if ($config.BackblazeB2.Enabled) {
        Write-Log "Starting Backblaze B2 sync"
        Sync-ToBackblaze -Config $config
    }
    
    # Send success email notification
    $backupInfo = @{
        CompressedFiles = $compressedFiles
        DatabaseDetails = $backupResult.DatabaseDetails
        TotalDatabases = $backupResult.TotalDatabases
        SuccessCount = $backupResult.SuccessCount
        FailureCount = $backupResult.FailureCount
        FailedDatabases = $backupResult.FailedDatabases
    }
    
    if ($backupResult.FailureCount -eq 0) {
        Write-Log "All database backups completed successfully"
        Send-EmailNotification -Config $config -BackupInfo $backupInfo -Success $true
    }
    else {
        Write-Log "$($backupResult.FailureCount) database backups failed" -Level "WARNING"
        Send-EmailNotification -Config $config -BackupInfo $backupInfo -Success $false
    }
    
    Write-Log "SQL Server backup script completed"
    exit 0
}
catch {
    # Try to log the error
    if ($script:logStream) {
        Write-Log "SQL Server backup script failed: $_" -Level "ERROR"
    }
    else {
        # If logging hasn't been initialized yet, write to console
        Write-Host "ERROR: SQL Server backup script failed: $_" -ForegroundColor Red
    }
    
    # Try to send failure email notification
    try {
        Send-EmailNotification -Config $config -ErrorMessage $_.ToString() -Success $false
    }
    catch {
        if ($script:logStream) {
            Write-Log "Failed to send email notification: $_" -Level "ERROR"
        }
        else {
            Write-Host "ERROR: Failed to send email notification: $_" -ForegroundColor Red
        }
    }
    
    exit 1
}
finally {
    # Always clean up temporary directories, even if errors occur
    try {
        Cleanup-TempDirectories -Config $config -BackupFolder $(if ($backupResult) { $backupResult.BackupFolder } else { $null })
    }
    catch {
        if ($script:logStream) {
            Write-Log "Error during final cleanup: $_" -Level "ERROR"
        }
        else {
            Write-Host "ERROR: Error during final cleanup: $_" -ForegroundColor Red
        }
    }
    
    # Stop log
    Stop-Log
}

#endregion
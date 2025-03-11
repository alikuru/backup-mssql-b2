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

function Backup-Databases {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    
    try {
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
        
        # Load SQL Server module if using it
        if ($Config.UseSQLPSModule -eq $true) {
            try {
                Import-Module SQLPS -DisableNameChecking -ErrorAction Stop
            }
            catch {
                Write-Log "Failed to import SQLPS module. Falling back to SMO." -Level "WARNING"
                [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null
                [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
            }
        }
        
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
            
            foreach ($database in $databasesToBackup) {
                $dbName = $database.Name
                $backupFile = Join-Path -Path $backupFolder -ChildPath "$dbName.bak"
                
                Write-Log "Starting backup of database: $dbName"
                
                $backup = New-Object Microsoft.SqlServer.Management.Smo.Backup
                $backup.Action = [Microsoft.SqlServer.Management.Smo.BackupActionType]::Database
                $backup.BackupSetDescription = "Full backup of $dbName"
                $backup.BackupSetName = "$dbName backup"
                $backup.Database = $dbName
                $backup.MediaDescription = "Disk"
                $backup.Devices.AddDevice($backupFile, [Microsoft.SqlServer.Management.Smo.DeviceType]::File)
                $backup.Initialize = $true
                
                # Execute the backup
                $backup.SqlBackup($server)
                
                Write-Log "Completed backup of database: $dbName to $backupFile"
                $backupFiles += $backupFile
            }
            
            return @{
                "BackupFolder" = $backupFolder
                "BackupFiles" = $backupFiles
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
        [string]$BackupFolder
    )
    
    try {
        # Check if 7-Zip is available
        $7zipPath = $Config.Compression.Path
        if (-not (Test-Path $7zipPath)) {
            throw "7-Zip executable not found at path: $7zipPath"
        }
        
        # Create compressed file
        $timestamp = Split-Path -Path $BackupFolder -Leaf
        $compressedFile = Join-Path -Path $Config.BackupPath -ChildPath "$timestamp.7z"
        
        Write-Log "Compressing backups to: $compressedFile"
        
        # Set compression level
        $compressionLevel = $Config.Compression.Level
        if (-not $compressionLevel) {
            $compressionLevel = 5  # Default compression level
        }
        
        # Compress the backup folder
        $arguments = "a -t7z `"$compressedFile`" `"$BackupFolder\*`" -mx=$compressionLevel"
        $process = Start-Process -FilePath $7zipPath -ArgumentList $arguments -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -ne 0) {
            throw "7-Zip compression failed with exit code: $($process.ExitCode)"
        }
        
        Write-Log "Compression completed successfully"
        
        # Remove the original backup folder to save space
        Remove-Item -Path $BackupFolder -Recurse -Force
        Write-Log "Removed original backup folder after compression"
        
        return $compressedFile
    }
    catch {
        Write-Log "Compression failed: $_" -Level "ERROR"
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
        $backupPath = $Config.BackupPath
        
        Write-Log "Checking for backups older than $retentionDays days"
        
        # Get all 7z files in the backup directory
        $backupFiles = Get-ChildItem -Path $backupPath -Filter "*.7z" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$retentionDays) }
        
        if ($backupFiles.Count -gt 0) {
            foreach ($file in $backupFiles) {
                Remove-Item -Path $file.FullName -Force
                Write-Log "Removed old backup: $($file.FullName)"
            }
            
            Write-Log "Removed $($backupFiles.Count) old backup files"
        }
        else {
            Write-Log "No old backups to remove"
        }
    }
    catch {
        Write-Log "Failed to remove old backups: $_" -Level "WARNING"
        # Continue execution even if cleanup fails
    }
}

function Remove-OldLogs {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config
    )
    
    try {
        $retentionDays = $Config.RetentionDays
        $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
        
        Write-Log "Checking for log files older than $retentionDays days"
        
        # Get all log files in the script directory
        $logFiles = Get-ChildItem -Path $scriptPath -Filter "Backup-SQLServer_*.log" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$retentionDays) }
        
        if ($logFiles.Count -gt 0) {
            foreach ($file in $logFiles) {
                Remove-Item -Path $file.FullName -Force
                Write-Log "Removed old log file: $($file.FullName)"
            }
            
            Write-Log "Removed $($logFiles.Count) old log files"
        }
        else {
            Write-Log "No old log files to remove"
        }
    }
    catch {
        Write-Log "Failed to remove old log files: $_" -Level "WARNING"
        # Continue execution even if log cleanup fails
    }
}

function Sync-ToBackblaze {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Config,
        
        [Parameter(Mandatory=$true)]
        [string]$CompressedFile
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
        
        Write-Log "Starting Backblaze B2 sync for: $CompressedFile"
        
        # Set B2 credentials as environment variables
        $env:B2_APPLICATION_KEY_ID = $b2Config.KeyId
        $env:B2_APPLICATION_KEY = $b2Config.ApplicationKey
        
        # Get the B2 CLI path
        $b2CliPath = $b2Config.CliPath
        if (-not (Test-Path $b2CliPath)) {
            throw "Backblaze B2 CLI not found at path: $b2CliPath"
        }
        
        # Authorize account
        $authorizeArgs = "authorize-account"
        $process = Start-Process -FilePath $b2CliPath -ArgumentList $authorizeArgs -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -ne 0) {
            throw "B2 authorization failed with exit code: $($process.ExitCode)"
        }
        
        # Upload file
        $fileName = Split-Path -Path $CompressedFile -Leaf
        $destinationPath = if ($b2Config.FolderPath) { "$($b2Config.FolderPath)/$fileName" } else { $fileName }
        
        $uploadArgs = "upload-file --noProgress $($b2Config.BucketName) `"$CompressedFile`" `"$destinationPath`""
        $process = Start-Process -FilePath $b2CliPath -ArgumentList $uploadArgs -NoNewWindow -PassThru -Wait
        
        if ($process.ExitCode -ne 0) {
            throw "B2 upload failed with exit code: $($process.ExitCode)"
        }
        
        Write-Log "Successfully uploaded backup to Backblaze B2: $destinationPath"
        
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
            "SQL Server Backup Successful - $(Get-Date -Format 'yyyy-MM-dd')"
        }
        else {
            "SQL Server Backup FAILED - $(Get-Date -Format 'yyyy-MM-dd')"
        }
        
        # Build email body
        $body = @"
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .success { color: green; }
        .failure { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h2>SQL Server Backup Report</h2>
    <p>Server: $($Config.SQLServer.ServerInstance)</p>
    <p>Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    
    <h3 class="$(if($Success){'success'}else{'failure'})">
        Status: $(if($Success){'SUCCESS'}else{'FAILURE'})
    </h3>
"@
        
        if ($Success) {
            $body += @"
    <h4>Backup Details:</h4>
    <ul>
        <li>Backup Location: $($BackupInfo.CompressedFile)</li>
        <li>Backup Size: $([math]::Round((Get-Item $BackupInfo.CompressedFile).Length / 1MB, 2)) MB</li>
        <li>Databases Backed Up: $($BackupInfo.DatabaseCount)</li>
    </ul>
"@
            
            if ($Config.BackblazeB2.Enabled) {
                $body += @"
    <p>Backup was successfully uploaded to Backblaze B2.</p>
"@
            }
        }
        else {
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

#endregion

#region Main Script Execution

# Initialize script
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:LogFile = Join-Path -Path $scriptPath -ChildPath "Backup-SQLServer_$timestamp.log"

Write-Log "SQL Server Backup Script started"
Write-Log "Using configuration file: $ConfigPath"

try {
    # Read configuration
    $config = Read-Config -ConfigPath $ConfigPath
    Write-Log "Configuration loaded successfully"
    
    # Backup databases
    Write-Log "Starting database backup process"
    $backupResult = Backup-Databases -Config $config
    
    # Compress backups
    Write-Log "Starting backup compression"
    $compressedFile = Compress-Backups -Config $config -BackupFolder $backupResult.BackupFolder
    
    # Remove old backups
    Write-Log "Starting backup rotation"
    Remove-OldBackups -Config $config
    
    # Remove old log files
    Write-Log "Starting log rotation"
    Remove-OldLogs -Config $config
    
    # Sync to Backblaze B2
    Write-Log "Starting Backblaze B2 sync"
    Sync-ToBackblaze -Config $config -CompressedFile $compressedFile
    
    # Send success email notification
    $backupInfo = @{
        CompressedFile = $compressedFile
        DatabaseCount = $backupResult.BackupFiles.Count
    }
    Send-EmailNotification -Config $config -Success $true -BackupInfo $backupInfo
    
    Write-Log "SQL Server Backup Script completed successfully"
    exit 0
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Log "SQL Server Backup Script failed: $errorMessage" -Level "ERROR"
    
    # Send failure email notification
    Send-EmailNotification -Config $config -Success $false -ErrorMessage $errorMessage
    
    exit 1
}

#endregion

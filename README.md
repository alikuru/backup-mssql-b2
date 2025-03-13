# SQL Server Backup Script

A PowerShell script for automated SQL Server database backups with compression, rotation, cloud synchronization, and email notifications.

Vibe coded with minor human intervention using Windsurf AI and Claude 3.7 Sonnet.

## Features

- Backs up all or specified SQL Server databases.
- Compresses backups using 7-Zip.
- Rotates backups based on configurable retention period.
- Synchronizes backups to Backblaze B2 cloud storage.
- Sends email notifications on success or failure.
- Fully configurable via JSON configuration file.

## Prerequisites

- Windows Server with PowerShell 5.1 or later.
- SQL Server instance.
- [7-Zip](https://www.7-zip.org/) installed.
- [Backblaze B2 CLI](https://www.backblaze.com/b2/docs/quick_command_line.html) installed (if using B2 sync).
- SMTP server access (if using email notifications).

## Installation

1. Clone or download this repository to your SQL Server.
2. Copy [config-sample.json](config-sample.json) to `config.json` and edit the new file to match your environment.
3. Test the script by running it manually.
4. Set up a scheduled task to run the script automatically.

## Configuration

The script is configured using the `config.json` file. Here's an explanation of each section:

### SQL Server Configuration

```json
"SQLServer": {
  "ServerInstance": "localhost",
  "UseIntegratedSecurity": true,
  "Username": "",
  "Password": "",
  "Databases": []
}
```

- `ServerInstance`: SQL Server instance name
- `UseIntegratedSecurity`: Set to `true` to use Windows authentication, `false` to use SQL authentication
- `Username` and `Password`: SQL Server credentials (only used if `UseIntegratedSecurity` is `false`)
- `Databases`: Array of database names to backup. Leave empty to backup all user databases.

### Backup Path and Retention

```json
"BackupPath": "C:\\SQLBackups",
"RetentionDays": 7,
```

- `BackupPath`: Local path where backups will be stored.
- `RetentionDays`: Number of days to keep backups before deletion.

### Compression Settings

```json
"Compression": {
  "Path": "C:\\Program Files\\7-Zip\\7z.exe",
  "Level": 5
}
```

- `Path`: Path to 7-Zip executable.
- `Level`: Compression level (0-9, where 9 is maximum compression).

### Backblaze B2 Configuration

```json
"BackblazeB2": {
  "Enabled": true,
  "KeyId": "",
  "ApplicationKey": "",
  "BucketName": "",
  "FolderPath": "SQLBackups",
  "CliPath": "C:\\Program Files\\Backblaze\\b2.exe"
}
```

- `Enabled`: Set to `true` to enable B2 sync, `false` to disable.
- `KeyId`: Your Backblaze B2 application key ID.
- `ApplicationKey`: Your Backblaze B2 application key.
- `BucketName`: Name of the B2 bucket to upload to.
- `FolderPath`: Optional folder path within the bucket.
- `CliPath`: Path to the B2 CLI executable.

### Email Notification Settings

```json
"Email": {
  "Enabled": true,
  "SmtpServer": "",
  "Port": 587,
  "EnableSsl": true,
  "Username": "",
  "Password": "",
  "From": "",
  "To": ""
}
```

- `Enabled`: Set to `true` to enable email notifications, `false` to disable.
- `SmtpServer`: SMTP server address.
- `Port`: SMTP server port.
- `EnableSsl`: Set to `true` to use SSL/TLS, `false` otherwise.
- `Username` and `Password`: SMTP server credentials.
- `From`: Sender email address.
- `To`: Recipient email address(es), comma-separated.

## Usage

### Manual Execution

```powershell
.\Backup-SQLServer.ps1 -ConfigPath ".\config.json"
```

### Scheduled Task

To set up a scheduled task to run the script daily:

1. Open Task Scheduler.
2. Create a new task.
3. Set the trigger to run daily at your preferred time.
4. Add a new action:
   - Action: Start a program.
   - Program/script: `powershell.exe`.
   - Arguments: `-ExecutionPolicy Bypass -File "C:\path\to\Backup-SQLServer.ps1" -ConfigPath "C:\path\to\config.json"`.

## Logging

The script creates a log file in the `logs` directory under the script directory, named `Backup-SQLServer_YYYYMMDD_HHMMSS.log`. This log contains detailed information about the backup process.

## Troubleshooting

This script is tested to work on the same machine where SQL Server is installed. If you are having connection issues, check if SQL Server Management Objects (SMO) is installed on the machine.

Also, please note that the SQLPS module is an older, deprecated SQL Server PowerShell module that is no longer maintained, while the [SqlServer module is the current](https://learn.microsoft.com/en-us/powershell/sql-server/sql-server-powershell?view=sqlserver-ps#:~:text=There%20are%20two%20SQL%20Server,but%20is%20no%20longer%20updated.), actively maintained module for managing SQL Server instances via PowerShell. You may try installing the SqlServer PowerShell module if it's not already installed:

```powershell
Install-Module -Name SqlServer -Force -SkipPublisherCheck
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# EntraChecks Logging System Guide

## Overview

The EntraChecks logging subsystem provides enterprise-grade logging capabilities with structured logging, multiple output targets, audit trails, and comprehensive error tracking. This guide covers how to use the logging system effectively.

## Features

- **Multiple Log Levels**: DEBUG, INFO, WARN, ERROR, CRITICAL
- **Structured Logging**: JSON format for easy parsing and analysis
- **Multiple Targets**: File, Console, EventLog
- **Audit Trail**: Separate audit log for compliance tracking
- **Log Rotation**: Automatic cleanup of old log files
- **Buffered Writes**: Performance optimization for high-volume logging
- **Error Context**: Full stack traces and error details
- **Session Tracking**: Unique session IDs for correlation

## Quick Start

### 1. Initialize Logging

```powershell
# Import the logging module
Import-Module .\Modules\EntraChecks-Logging.psm1

# Initialize with default settings
Initialize-LoggingSubsystem -LogDirectory ".\Logs" -MinimumLevel INFO

# Initialize with custom settings
Initialize-LoggingSubsystem `
    -LogDirectory "C:\Logs\EntraChecks" `
    -MinimumLevel DEBUG `
    -Targets @('File', 'Console', 'EventLog') `
    -RetentionDays 90 `
    -StructuredLogging `
    -MaxFileSizeMB 100
```

### 2. Write Log Entries

```powershell
# Basic logging
Write-Log -Level INFO -Message "Assessment started" -Category "System"

# Logging with custom properties
Write-Log -Level INFO -Message "User data retrieved" -Category "API" -Properties @{
    UserCount = 1523
    Duration = 2.5
    Endpoint = "/users"
}

# Error logging with ErrorRecord
try {
    # Your code
}
catch {
    Write-Log -Level ERROR -Message "Operation failed" -Category "Operation" -ErrorRecord $_
}

# Warning logging
Write-Log -Level WARN -Message "API rate limit approaching" -Category "API" -Properties @{
    RemainingCalls = 50
    ResetTime = "2024-01-15T14:30:00Z"
}
```

### 3. Write Audit Logs

```powershell
# Authentication events
Write-AuditLog `
    -EventType "AuthenticationSuccess" `
    -Description "User authenticated to Microsoft Graph" `
    -TargetObject "admin@contoso.com" `
    -Result "Success"

# Configuration changes
Write-AuditLog `
    -EventType "ConfigurationChanged" `
    -Description "Assessment scope modified" `
    -Details @{
        ChangedBy = "admin@contoso.com"
        OldValue = "Core"
        NewValue = "Core,IdentityProtection,Devices"
    } `
    -Result "Success"

# Finding detection
Write-AuditLog `
    -EventType "FindingDetected" `
    -Description "Critical security issue detected" `
    -TargetObject "Conditional Access Policy: Block Legacy Auth" `
    -Details @{
        Severity = "Critical"
        Category = "Authentication"
    } `
    -Result "Warning"
```

### 4. Cleanup

```powershell
# Flush buffers and close log files
Stop-Logging
```

## Log Levels

| Level | Usage | Color |
|-------|-------|-------|
| **DEBUG** | Detailed diagnostic information for troubleshooting | Gray |
| **INFO** | General informational messages about normal operation | White |
| **WARN** | Warning messages for potentially problematic situations | Yellow |
| **ERROR** | Error messages for failures that don't stop execution | Red |
| **CRITICAL** | Critical errors that may cause application failure | Magenta |

## Audit Event Types

| Event Type | Description |
|------------|-------------|
| `SessionStarted` | Assessment session started |
| `SessionEnded` | Assessment session ended |
| `AuthenticationSuccess` | Successful authentication |
| `AuthenticationFailure` | Failed authentication attempt |
| `CheckExecuted` | Security check or module executed |
| `FindingDetected` | Security finding detected |
| `ReportGenerated` | Report generated |
| `ConfigurationChanged` | Configuration modified |
| `DataExported` | Data exported |
| `SnapshotCreated` | Compliance snapshot created |
| `ComparisonPerformed` | Snapshot comparison performed |
| `ModuleLoaded` | Module imported |

## Log File Locations

### Standard Log Files

```
.\Logs\
├── entrachecks-20240115.log          # Daily log file
├── entrachecks-20240115-143000.log   # Rotated log (if size exceeded)
└── audit-20240115.json               # Daily audit log (always JSON)
```

### Log File Rotation

- **Size-based**: When a log file exceeds `MaxFileSizeMB` (default: 100MB), it's archived with a timestamp
- **Age-based**: Log files older than `RetentionDays` (default: 90) are automatically deleted

## Structured vs. Traditional Logging

### Traditional Format

```
[2024-01-15T14:30:45.123Z] [INFO] [API] User data retrieved | UserCount=1523, Duration=2.5
```

### Structured Format (JSON)

```json
{
  "Timestamp": "2024-01-15T14:30:45.123Z",
  "Level": "INFO",
  "Category": "API",
  "Message": "User data retrieved",
  "SessionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "ProcessId": 12345,
  "ThreadId": 8,
  "User": "admin",
  "Computer": "WORKSTATION01",
  "UserCount": 1523,
  "Duration": 2.5
}
```

**Benefits of Structured Logging:**
- Easy parsing and querying
- Integration with log analysis tools (Splunk, ELK, etc.)
- Machine-readable format
- Preserves data types

## Integration with Existing Code

### In Main Scripts

```powershell
# Start-EntraChecks.ps1
Import-Module .\Modules\EntraChecks-Logging.psm1 -Force
Initialize-LoggingSubsystem -LogDirectory ".\Logs" -MinimumLevel INFO

Write-Log -Level INFO -Message "EntraChecks started" -Category "System"
Write-AuditLog -EventType "SessionStarted" -Description "Assessment session started"

try {
    # Your code
}
catch {
    Write-Log -Level ERROR -Message "Unhandled error" -Category "System" -ErrorRecord $_
}
finally {
    Stop-Logging
}
```

### In Module Functions

```powershell
# In your module .psm1 file
$loggingModule = Join-Path $PSScriptRoot "EntraChecks-Logging.psm1"
if (Test-Path $loggingModule) {
    Import-Module $loggingModule -Force -ErrorAction SilentlyContinue
}

function Test-MySecurityCheck {
    Write-Log -Level INFO -Message "Starting security check" -Category "SecurityCheck"

    try {
        # Check logic here
        $results = Get-SecurityData

        Write-Log -Level INFO -Message "Security check completed" -Category "SecurityCheck" -Properties @{
            ResultCount = $results.Count
            Duration = 5.2
        }

        return $results
    }
    catch {
        Write-Log -Level ERROR -Message "Security check failed" -Category "SecurityCheck" -ErrorRecord $_
        throw
    }
}
```

### In Check Functions

```powershell
function Test-PasswordNeverExpires {
    Write-Log -Level INFO -Message "Checking for passwords that never expire" -Category "PasswordPolicy"

    try {
        $users = Get-MgUser -Filter "passwordPolicies eq 'DisablePasswordExpiration'" -All

        if ($users.Count -gt 0) {
            Write-Log -Level WARN -Message "Found users with password never expires" -Category "PasswordPolicy" -Properties @{
                UserCount = $users.Count
            }

            foreach ($user in $users) {
                Add-Finding `
                    -Status "FAIL" `
                    -Object $user.UserPrincipalName `
                    -Description "Password set to never expire" `
                    -Remediation "Configure password expiration policy"
            }
        }
        else {
            Write-Log -Level INFO -Message "No users found with password never expires" -Category "PasswordPolicy"
        }

        return $users
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to check password policies" -Category "PasswordPolicy" -ErrorRecord $_
        throw
    }
}
```

## Advanced Features

### Custom Log Properties

Add contextual information to any log entry:

```powershell
Write-Log -Level INFO -Message "API call completed" -Category "API" -Properties @{
    Endpoint = "/users"
    Method = "GET"
    StatusCode = 200
    Duration = 1.23
    ResponseSize = 45678
    TenantId = "12345"
}
```

### Error Context

Capture full error details:

```powershell
try {
    Invoke-SomeOperation
}
catch {
    Write-Log -Level ERROR `
        -Message "Operation failed" `
        -Category "Operation" `
        -ErrorRecord $_ `
        -Properties @{
            OperationId = "OP-12345"
            RetryCount = 3
        }
}
```

### Session Tracking

All logs in a session share the same `SessionId` for correlation:

```powershell
$config = Get-LoggingConfiguration
Write-Host "Current Session ID: $($config.SessionId)"

# All logs will include this SessionId for filtering
Write-Log -Level INFO -Message "Step 1" -Category "Workflow"
Write-Log -Level INFO -Message "Step 2" -Category "Workflow"
Write-Log -Level INFO -Message "Step 3" -Category "Workflow"
```

### Dynamic Log Level

Change log level during execution:

```powershell
# Start with INFO
Initialize-LoggingSubsystem -LogDirectory ".\Logs" -MinimumLevel INFO

# DEBUG messages won't appear
Write-Log -Level DEBUG -Message "Debug message" -Category "Test"

# Enable DEBUG for troubleshooting
Set-LogLevel -Level DEBUG

# Now DEBUG messages appear
Write-Log -Level DEBUG -Message "Debug message now visible" -Category "Test"
```

### Buffered Writes

Logs are buffered for performance (default: 100 entries):

```powershell
# Logs are buffered automatically
for ($i = 1; $i -le 1000; $i++) {
    Write-Log -Level INFO -Message "Processing item $i" -Category "Batch"
}

# Buffer is flushed automatically every 100 entries
# Or flush manually
Flush-LogBuffer
```

## Best Practices

### 1. Choose Appropriate Log Levels

```powershell
# ✅ Good
Write-Log -Level DEBUG -Message "Entering function with parameters: $params" -Category "Debug"
Write-Log -Level INFO -Message "Assessment completed successfully" -Category "Assessment"
Write-Log -Level WARN -Message "API rate limit at 80%" -Category "API"
Write-Log -Level ERROR -Message "Failed to retrieve data" -Category "API" -ErrorRecord $_
Write-Log -Level CRITICAL -Message "Authentication failed - cannot continue" -Category "Auth"

# ❌ Bad
Write-Log -Level INFO -Message "x = 5, y = 10" -Category "Debug"  # Should be DEBUG
Write-Log -Level ERROR -Message "Assessment completed" -Category "Assessment"  # Should be INFO
```

### 2. Use Meaningful Categories

```powershell
# ✅ Good - Clear, specific categories
Write-Log -Level INFO -Message "..." -Category "Authentication"
Write-Log -Level INFO -Message "..." -Category "API"
Write-Log -Level INFO -Message "..." -Category "SecurityCheck"
Write-Log -Level INFO -Message "..." -Category "Reporting"

# ❌ Bad - Vague categories
Write-Log -Level INFO -Message "..." -Category "General"
Write-Log -Level INFO -Message "..." -Category "Stuff"
Write-Log -Level INFO -Message "..." -Category "Test"
```

### 3. Add Context with Properties

```powershell
# ✅ Good - Rich context
Write-Log -Level INFO -Message "User data retrieved" -Category "API" -Properties @{
    Endpoint = "/users"
    UserCount = 1523
    Duration = 2.5
    Filter = "accountEnabled eq true"
}

# ❌ Bad - No context
Write-Log -Level INFO -Message "Got 1523 users in 2.5 seconds" -Category "API"
```

### 4. Always Log Errors with ErrorRecord

```powershell
# ✅ Good - Full error context
try {
    Invoke-Operation
}
catch {
    Write-Log -Level ERROR -Message "Operation failed" -Category "Operation" -ErrorRecord $_
}

# ❌ Bad - Loses stack trace
try {
    Invoke-Operation
}
catch {
    Write-Log -Level ERROR -Message "Error: $($_.Exception.Message)" -Category "Operation"
}
```

### 5. Use Audit Logs for Compliance Events

```powershell
# ✅ Good - Separate audit trail
Write-AuditLog -EventType "FindingDetected" -Description "..." -Result "Warning"

# ❌ Bad - Mixed with regular logs
Write-Log -Level INFO -Message "Finding detected: ..." -Category "Finding"
```

## Troubleshooting

### Logs Not Appearing

1. Check if logging is initialized:
   ```powershell
   $config = Get-LoggingConfiguration
   if ($config.Initialized) { Write-Host "Logging is initialized" }
   ```

2. Check minimum log level:
   ```powershell
   Get-LoggingConfiguration | Select-Object MinLevel
   # If MinLevel is INFO, DEBUG messages won't appear
   ```

3. Manually flush buffer:
   ```powershell
   Flush-LogBuffer
   ```

### Log Files Not Found

Check the configured log directory:

```powershell
$logFile = Get-LogFilePath
Write-Host "Log file: $logFile"
Test-Path $logFile
```

### EventLog Errors

EventLog target requires admin privileges:

```powershell
# Check if EventLog is in targets
$config = Get-LoggingConfiguration
if ($config.Targets -contains 'EventLog') {
    # EventLog is enabled but may fail without admin rights
    # Fallback to File and Console only
}
```

## Performance Considerations

- **Buffering**: Logs are buffered (default 100 entries) before writing to disk
- **Structured Logging**: JSON serialization has slight overhead vs. text format
- **Log Levels**: Use appropriate levels to control volume (DEBUG = high volume)
- **File Size**: Monitor `MaxFileSizeMB` to prevent excessive disk usage
- **Retention**: Set appropriate `RetentionDays` to manage disk space

## Integration with SIEM/Log Analysis Tools

### Splunk

```powershell
# Enable structured logging for easy Splunk ingestion
Initialize-LoggingSubsystem -LogDirectory ".\Logs" -StructuredLogging

# Configure Splunk to monitor the log directory
# Splunk will automatically parse the JSON format
```

### ELK Stack (Elasticsearch, Logstash, Kibana)

```powershell
# Use structured logging
Initialize-LoggingSubsystem -LogDirectory ".\Logs" -StructuredLogging

# Configure Filebeat or Logstash to read from log directory
# JSON format is natively supported
```

### Azure Monitor / Application Insights

```powershell
# Future enhancement: Direct integration with Application Insights
# Currently: Export logs and upload to Azure Monitor
```

## Conclusion

The EntraChecks logging system provides enterprise-grade logging capabilities that improve troubleshooting, compliance tracking, and operational visibility. Follow the best practices in this guide to maximize the value of your logs.

For more information, see:
- [Example-Logging-Usage.ps1](../Examples/Example-Logging-Usage.ps1)
- [EntraChecks-Logging.psm1](../Modules/EntraChecks-Logging.psm1)

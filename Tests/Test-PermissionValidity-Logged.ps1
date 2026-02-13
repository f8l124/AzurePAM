<#
.SYNOPSIS
    Test-PermissionValidity-Logged.ps1 - Validate permissions with file logging

.DESCRIPTION
    Tests each permission individually and logs ALL output to a file,
    even if PowerShell crashes.
#>

# Setup logging
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $PSScriptRoot "PermissionTest-$timestamp.log"

function Write-Log {
    param(
        [string]$Message,
        [string]$Color = "White"
    )

    $logMessage = "[$(Get-Date -Format 'HH:mm:ss')] $Message"

    # Write to console
    Write-Host $Message -ForegroundColor $Color

    # Write to file immediately (flush)
    Add-Content -Path $logFile -Value $logMessage -Force
}

Write-Log "==================================================================" "Cyan"
Write-Log "  Microsoft Graph Permission Validator (with Logging)            " "Cyan"
Write-Log "==================================================================" "Cyan"
Write-Log ""
Write-Log "Log file: $logFile" "Gray"
Write-Log ""

# All permissions to test (CORRECTED 2026-02-11)
$allPermissions = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "SecurityEvents.Read.All",
    "AuditLog.Read.All",
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyUser.Read.All",
    "Device.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "InformationProtectionPolicy.Read",        # FIXED: was ComplianceManager.Read.All (no .All suffix)
    "BitLockerKey.ReadBasic.All"               # For BitLocker/device encryption compliance
)

$results = @()

foreach ($permission in $allPermissions) {
    Write-Log "----------------------------------------------------------------" "Gray"
    Write-Log "Testing: $permission" "Cyan"

    # Disconnect first
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Log "  Disconnected previous session" "Gray"
    }
    catch {
        Write-Log "  Could not disconnect: $($_.Exception.Message)" "Yellow"
    }

    $result = @{
        Permission = $permission
        Status = "Unknown"
        Error = ""
    }

    try {
        Write-Log "  Attempting connection..." "Gray"

        # Try to connect with this permission
        $null = Connect-MgGraph -Scopes $permission -NoWelcome -ErrorAction Stop

        Write-Log "  Connection command completed" "Gray"

        # Check if context exists
        $context = Get-MgContext

        if ($context) {
            Write-Log "  SUCCESS - Context retrieved" "Green"
            Write-Log "  Account: $($context.Account)" "White"
            Write-Log "  Scopes: $($context.Scopes -join ', ')" "White"

            $result.Status = "SUCCESS"

            # Disconnect
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Write-Log "  Disconnected" "Gray"
        }
        else {
            Write-Log "  WARNING - Connection succeeded but no context" "Yellow"
            $result.Status = "NO_CONTEXT"
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        Write-Log "  FAILED: $errorMsg" "Red"

        $result.Status = "FAILED"
        $result.Error = $errorMsg

        # Categorize error
        if ($errorMsg -match "not found|invalid|does not exist|unknown") {
            Write-Log "  -> Permission name is INVALID (doesn't exist)" "Red"
            $result.Status = "INVALID"
        }
        elseif ($errorMsg -match "consent|admin|approval") {
            Write-Log "  -> Requires admin consent or license" "Yellow"
            $result.Status = "NEEDS_CONSENT"
        }
        elseif ($errorMsg -match "InteractiveBrowserCredential|authentication failed") {
            Write-Log "  -> Authentication failed (browser/redirect issue)" "Red"
            $result.Status = "AUTH_FAILED"
        }
    }

    $results += $result
    Write-Log "" "White"

    # Small delay between tests
    Start-Sleep -Milliseconds 1000
}

# Summary
Write-Log "==================================================================" "Cyan"
Write-Log "                        SUMMARY                                   " "Cyan"
Write-Log "==================================================================" "Cyan"
Write-Log ""

$successCount = ($results | Where-Object { $_.Status -eq "SUCCESS" }).Count
$invalidCount = ($results | Where-Object { $_.Status -eq "INVALID" }).Count
$failedCount = ($results | Where-Object { $_.Status -eq "FAILED" -or $_.Status -eq "AUTH_FAILED" }).Count
$consentCount = ($results | Where-Object { $_.Status -eq "NEEDS_CONSENT" }).Count

Write-Log "Total permissions tested: $($allPermissions.Count)" "White"
Write-Log "  SUCCESS: $successCount" "Green"
Write-Log "  INVALID (doesn't exist): $invalidCount" "Red"
Write-Log "  FAILED (auth/other): $failedCount" "Red"
Write-Log "  NEEDS CONSENT: $consentCount" "Yellow"
Write-Log ""

if ($successCount -gt 0) {
    Write-Log "SUCCESSFUL PERMISSIONS:" "Green"
    foreach ($r in ($results | Where-Object { $_.Status -eq "SUCCESS" })) {
        Write-Log "  [OK] $($r.Permission)" "Green"
    }
    Write-Log ""
}

if ($invalidCount -gt 0) {
    Write-Log "INVALID PERMISSIONS (need to be replaced):" "Red"
    foreach ($r in ($results | Where-Object { $_.Status -eq "INVALID" })) {
        Write-Log "  [X] $($r.Permission)" "Red"
    }
    Write-Log ""
}

if ($failedCount -gt 0) {
    Write-Log "FAILED PERMISSIONS:" "Red"
    foreach ($r in ($results | Where-Object { $_.Status -eq "FAILED" -or $_.Status -eq "AUTH_FAILED" })) {
        Write-Log "  [X] $($r.Permission) - $($r.Error.Substring(0, [Math]::Min(60, $r.Error.Length)))" "Red"
    }
    Write-Log ""
}

Write-Log "Full log saved to: $logFile" "Cyan"
Write-Log ""
Write-Log "Press Enter to exit..."
Read-Host

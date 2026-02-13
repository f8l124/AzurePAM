<#
.SYNOPSIS
    Test-PermissionValidity.ps1 - Validate each Graph permission individually

.DESCRIPTION
    Tests each permission scope one-by-one to identify which are:
    - Valid and available
    - Invalid/renamed
    - Available but blocked in your tenant
#>

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  Microsoft Graph Permission Validator                          " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Testing each permission individually to find issues..." -ForegroundColor Yellow
Write-Host ""

# All permissions EntraChecks tries to request (CORRECTED 2026-02-11)
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

$validPermissions = @()
$invalidPermissions = @()
$blockedPermissions = @()

foreach ($permission in $allPermissions) {
    Write-Host "Testing: $permission" -ForegroundColor Cyan -NoNewline

    # Disconnect any existing session
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    try {
        # Try to connect with just this one permission
        Connect-MgGraph -Scopes $permission -NoWelcome -ErrorAction Stop | Out-Null

        $context = Get-MgContext
        if ($context) {
            Write-Host " [OK]" -ForegroundColor Green
            $validPermissions += $permission
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
    }
    catch {
        $errorMessage = $_.Exception.Message

        # Check error type
        if ($errorMessage -match "not found|invalid|does not exist|unknown") {
            Write-Host " [INVALID - Permission doesn't exist]" -ForegroundColor Red
            $invalidPermissions += $permission
        }
        elseif ($errorMessage -match "consent|admin|approval|blocked") {
            Write-Host " [BLOCKED - Needs admin consent or license]" -ForegroundColor Yellow
            $blockedPermissions += $permission
        }
        else {
            Write-Host " [ERROR - $($errorMessage.Substring(0, [Math]::Min(50, $errorMessage.Length)))]" -ForegroundColor Red
            $invalidPermissions += $permission
        }
    }

    Start-Sleep -Milliseconds 500
}

# Summary
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "                        RESULTS                                   " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""

if ($validPermissions.Count -gt 0) {
    Write-Host "VALID PERMISSIONS ($($validPermissions.Count)):" -ForegroundColor Green
    foreach ($perm in $validPermissions) {
        Write-Host "  [OK] $perm" -ForegroundColor Green
    }
    Write-Host ""
}

if ($blockedPermissions.Count -gt 0) {
    Write-Host "BLOCKED PERMISSIONS ($($blockedPermissions.Count)):" -ForegroundColor Yellow
    Write-Host "(Valid permissions but require admin consent or missing license)" -ForegroundColor Gray
    foreach ($perm in $blockedPermissions) {
        Write-Host "  [!] $perm" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($invalidPermissions.Count -gt 0) {
    Write-Host "INVALID PERMISSIONS ($($invalidPermissions.Count)):" -ForegroundColor Red
    Write-Host "(These permission names don't exist in Microsoft Graph)" -ForegroundColor Gray
    foreach ($perm in $invalidPermissions) {
        Write-Host "  [X] $perm" -ForegroundColor Red
    }
    Write-Host ""
}

# Recommendations
Write-Host "RECOMMENDATIONS:" -ForegroundColor Cyan
Write-Host ""

if ($invalidPermissions.Count -gt 0) {
    Write-Host "INVALID PERMISSIONS FOUND!" -ForegroundColor Red
    Write-Host "These permission names have likely changed. Check Microsoft's documentation:" -ForegroundColor Yellow
    Write-Host "  https://learn.microsoft.com/en-us/graph/permissions-reference" -ForegroundColor White
    Write-Host ""

    Write-Host "NOTE: All permissions have been corrected as of 2026-02-11." -ForegroundColor Yellow
    Write-Host "If you see invalid permissions, update your scripts." -ForegroundColor White
    Write-Host ""
}

if ($validPermissions.Count -eq $allPermissions.Count) {
    Write-Host "All permissions are valid! The issue is likely:" -ForegroundColor Green
    Write-Host "  - Requesting too many at once" -ForegroundColor White
    Write-Host "  - Some require licenses you don't have" -ForegroundColor White
    Write-Host "  - Conditional Access blocking the request" -ForegroundColor White
}
elseif ($validPermissions.Count -gt 0) {
    Write-Host "Mix of valid and invalid permissions." -ForegroundColor Yellow
    Write-Host "Update EntraChecks to only request the VALID ones above." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press Enter to exit..."
Read-Host

<#
.SYNOPSIS
    Grant-AdminConsent.ps1 - Grants admin consent for EntraChecks. All permissions are read only.

.DESCRIPTION
    Updates and fixes:
    - Uses corrected Microsoft Graph permission names
    - Tries browser auth first (more reliable than device code)
    - Falls back to device code if browser fails
    - Falls back to core-only permissions if licenses missing
    - Proper error handling and diagnostics

.NOTES
    Requires: Global Administrator role
    Permissions current based on Microsoft Graph API documentation as of 2026-02-11.
#>

# UTF-8 encoding fix
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
}
catch { Write-Verbose "Encoding not settable in this host: $_" }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  EntraChecks - Grant Admin Consent (Final Solution)          " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script will grant admin consent for Microsoft Graph API." -ForegroundColor White
Write-Host "You must be a GLOBAL ADMINISTRATOR to continue." -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Are you a Global Administrator? (Y/N)"
if ($confirm -ne 'Y') {
    Write-Host "Exiting." -ForegroundColor Red
    exit
}

# All permissions with read-only access
$allScopes = @(
    # Core permissions (no license required)
    "Directory.Read.All",
    "Policy.Read.All",
    "AuditLog.Read.All",
    "Device.Read.All",

    # Security (no license required)
    "SecurityEvents.Read.All",               # Required for Secure Score API

    # Information Protection (no license required)
    "InformationProtectionPolicy.Read",      # Special case: no .All suffix

    # Device Security (requires Windows Pro/Enterprise)
    "BitLockerKey.ReadBasic.All",            # For BitLocker/device encryption compliance

    # Identity Protection (requires Azure AD Premium P2)
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyUser.Read.All",

    # Intune (requires Intune license)
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All"
)

# Core permissions (fallback if license-dependent permissions fail)
$coreScopes = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "AuditLog.Read.All",
    "Device.Read.All",
    "SecurityEvents.Read.All",
    "InformationProtectionPolicy.Read",
    "BitLockerKey.ReadBasic.All"
)

Write-Host ""
Write-Host "Permissions to request:" -ForegroundColor Cyan
Write-Host ""
Write-Host "CORE (work in any tenant):" -ForegroundColor Green
$coreScopes | ForEach-Object { Write-Host "  [OK] $_" -ForegroundColor White }
Write-Host ""
Write-Host "PREMIUM (require Azure AD P2 or Intune):" -ForegroundColor Yellow
$allScopes | Where-Object { $_ -notin $coreScopes } | ForEach-Object {
    Write-Host "  [!] $_" -ForegroundColor White
}
Write-Host ""

# Function to test connection
function Test-GraphConnection {
    try {
        $context = Get-MgContext
        if ($context -and $context.Account) {
            Write-Host ""
            Write-Host "================================================================" -ForegroundColor Green
            Write-Host "                   SUCCESS!                                    " -ForegroundColor Green
            Write-Host "================================================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "Admin consent granted!" -ForegroundColor Green
            Write-Host "Connected as: $($context.Account)" -ForegroundColor White
            Write-Host "Tenant: $($context.TenantId)" -ForegroundColor White
            Write-Host "Auth Type: $($context.AuthType)" -ForegroundColor White
            Write-Host ""
            Write-Host "Granted scopes:" -ForegroundColor Cyan
            $context.Scopes | Sort-Object | ForEach-Object {
                Write-Host "  [OK] $_" -ForegroundColor White
            }
            Write-Host ""
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

# Attempt 1: Browser authentication with ALL permissions
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "ATTEMPT 1: Browser Authentication (All Permissions)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "A browser window will open." -ForegroundColor Yellow
Write-Host "You must:" -ForegroundColor Yellow
Write-Host "  1. Sign in as Global Administrator" -ForegroundColor White
Write-Host "  2. Check 'Consent on behalf of your organization'" -ForegroundColor White
Write-Host "  3. Click 'Accept'" -ForegroundColor White
Write-Host ""
Read-Host "Press Enter to open browser"

try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Opening browser..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes $allScopes -Audience 'organizations' -NoWelcome -ErrorAction Stop

    if (Test-GraphConnection) {
        Write-Host "EntraChecks will work with ALL features enabled!" -ForegroundColor Green
        Write-Host ""
        Disconnect-MgGraph | Out-Null
        Write-Host "Press Enter to exit..."
        Read-Host
        exit 0
    }
}
catch {
    Write-Host ""
    Write-Host "Browser authentication failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""

    # Check if it's a license issue
    if ($_.Exception.Message -match "consent|admin|approval|license") {
        Write-Host "This may be due to missing Premium licenses (Azure AD P2/Intune)." -ForegroundColor Yellow
        Write-Host "Will try CORE permissions only..." -ForegroundColor Yellow
    }
    else {
        Write-Host "Will try device code authentication..." -ForegroundColor Yellow
    }
}

# Attempt 2: Browser authentication with CORE permissions only
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "ATTEMPT 2: Browser Authentication (Core Permissions Only)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Requesting only CORE permissions (no premium licenses needed)." -ForegroundColor Yellow
Write-Host ""
Read-Host "Press Enter to open browser"

try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Opening browser..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes $coreScopes -Audience 'organizations' -NoWelcome -ErrorAction Stop

    if (Test-GraphConnection) {
        Write-Host "EntraChecks will work with BASIC features." -ForegroundColor Green
        Write-Host ""
        Write-Host "NOTE: Some advanced features disabled (no Premium licenses):" -ForegroundColor Yellow
        Write-Host "  - Identity Protection (requires Azure AD Premium P2)" -ForegroundColor White
        Write-Host "  - Intune device management (requires Intune license)" -ForegroundColor White
        Write-Host ""
        Disconnect-MgGraph | Out-Null
        Write-Host "Press Enter to exit..."
        Read-Host
        exit 0
    }
}
catch {
    Write-Host ""
    Write-Host "Browser authentication failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Browser authentication is blocked or failing." -ForegroundColor Yellow
    Write-Host "Will try device code authentication..." -ForegroundColor Yellow
}

# Attempt 3: Device code authentication with CORE permissions
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "ATTEMPT 3: Device Code Authentication (Core Permissions)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Device code authentication:" -ForegroundColor Yellow
Write-Host "  - Copy the code shown below" -ForegroundColor White
Write-Host "  - Go to: https://microsoft.com/devicelogin" -ForegroundColor White
Write-Host "  - Paste the code and sign in" -ForegroundColor White
Write-Host ""
Read-Host "Press Enter to continue"

try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "COPY THE CODE BELOW AND GO TO:" -ForegroundColor Yellow
    Write-Host "https://microsoft.com/devicelogin" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host ""

    # Device code with explicit audience parameter (as suggested by error message)
    Connect-MgGraph -Scopes $coreScopes -Audience 'organizations' -UseDeviceAuthentication -ErrorAction Stop

    if (Test-GraphConnection) {
        Write-Host "EntraChecks will work with BASIC features." -ForegroundColor Green
        Write-Host ""
        Disconnect-MgGraph | Out-Null
        Write-Host "Press Enter to exit..."
        Read-Host
        exit 0
    }
}
catch {
    Write-Host ""
    Write-Host "Device code authentication failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
}

# All attempts failed
Write-Host ""
Write-Host "================================================================" -ForegroundColor Red
Write-Host "                   ALL ATTEMPTS FAILED                         " -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
Write-Host ""
Write-Host "None of the authentication methods worked." -ForegroundColor Red
Write-Host ""
Write-Host "POSSIBLE CAUSES:" -ForegroundColor Yellow
Write-Host "  1. Conditional Access policy blocking PowerShell/Graph access" -ForegroundColor White
Write-Host "  2. Microsoft Graph PowerShell app disabled in your tenant" -ForegroundColor White
Write-Host "  3. Network/proxy blocking authentication" -ForegroundColor White
Write-Host "  4. You are not a Global Administrator" -ForegroundColor White
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Cyan
Write-Host "  1. Check Azure AD > Enterprise Applications" -ForegroundColor White
Write-Host "     Search for 'Microsoft Graph PowerShell'" -ForegroundColor White
Write-Host "     Verify it's enabled and not blocked" -ForegroundColor White
Write-Host ""
Write-Host "  2. Check Azure AD > Security > Conditional Access" -ForegroundColor White
Write-Host "     Look for policies blocking PowerShell or Graph" -ForegroundColor White
Write-Host ""
Write-Host "  3. Check Microsoft Graph PowerShell module version:" -ForegroundColor White
Write-Host "     Get-Module Microsoft.Graph -ListAvailable" -ForegroundColor Gray
Write-Host "     Update-Module Microsoft.Graph -Force" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. Contact your Azure AD administrator" -ForegroundColor White
Write-Host ""

Write-Host "Press Enter to exit..."
Read-Host

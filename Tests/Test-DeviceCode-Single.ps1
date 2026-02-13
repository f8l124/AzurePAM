<#
.SYNOPSIS
    Test-DeviceCode-Single.ps1 - Test device code with single permission

.DESCRIPTION
    Tests if device code authentication works at all with just one permission
#>

Write-Host ""
Write-Host "=== Testing Device Code with Single Permission ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Testing if device code authentication works with:" -ForegroundColor Yellow
Write-Host "  - Just ONE permission (User.Read.All)" -ForegroundColor White
Write-Host "  - Device code flow (not browser)" -ForegroundColor White
Write-Host ""

try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Starting device code authentication..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "COPY THE CODE SHOWN BELOW" -ForegroundColor Yellow
    Write-Host "GO TO: https://microsoft.com/devicelogin" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host ""

    Connect-MgGraph -Scopes "User.Read.All" -UseDeviceAuthentication -NoWelcome -ErrorAction Stop

    Write-Host ""
    Write-Host "SUCCESS! Device code works!" -ForegroundColor Green
    Write-Host ""

    $context = Get-MgContext
    Write-Host "Account: $($context.Account)" -ForegroundColor White
    Write-Host "Tenant: $($context.TenantId)" -ForegroundColor White
    Write-Host "Auth Type: $($context.AuthType)" -ForegroundColor White
    Write-Host ""

    Write-Host "DIAGNOSIS:" -ForegroundColor Cyan
    Write-Host "  Device code authentication WORKS!" -ForegroundColor Green
    Write-Host "  The issue is with requesting multiple permissions," -ForegroundColor Yellow
    Write-Host "  OR with specific permissions in the list." -ForegroundColor Yellow
    Write-Host ""

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host ""
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "DIAGNOSIS:" -ForegroundColor Cyan
    Write-Host "  Device code authentication is BLOCKED in your tenant." -ForegroundColor Red
    Write-Host ""
    Write-Host "LIKELY CAUSES:" -ForegroundColor Yellow
    Write-Host "  1. Conditional Access policy blocking device code flow" -ForegroundColor White
    Write-Host "  2. Authentication policy doesn't allow device code" -ForegroundColor White
    Write-Host "  3. Microsoft Graph PowerShell app is disabled/restricted" -ForegroundColor White
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Cyan
    Write-Host "  1. Check Azure AD > Security > Conditional Access" -ForegroundColor White
    Write-Host "  2. Check if 'Microsoft Graph PowerShell' enterprise app exists" -ForegroundColor White
    Write-Host "  3. Check Authentication Methods policies" -ForegroundColor White
    Write-Host ""
}

Write-Host "Press Enter to exit..."
Read-Host

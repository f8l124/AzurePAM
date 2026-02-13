<#
.SYNOPSIS
    Test-GraphAuth-Simple.ps1 - Minimal Graph auth test

.DESCRIPTION
    Tests authentication with just ONE simple permission to isolate the issue
#>

Write-Host ""
Write-Host "=== Simple Graph Auth Test ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Testing with just ONE permission: User.Read.All" -ForegroundColor Yellow
Write-Host "This is the most basic permission - should always work." -ForegroundColor Gray
Write-Host ""

# Disconnect any existing session
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

Write-Host "Starting authentication..." -ForegroundColor Cyan
Write-Host "A browser will open. Sign in and click Accept." -ForegroundColor Gray
Write-Host ""

try {
    # Try with just one simple scope
    Connect-MgGraph -Scopes "User.Read.All" -NoWelcome -ErrorAction Stop

    Write-Host ""
    Write-Host "SUCCESS! Authentication worked!" -ForegroundColor Green
    Write-Host ""

    $context = Get-MgContext
    Write-Host "Account: $($context.Account)" -ForegroundColor White
    Write-Host "Tenant: $($context.TenantId)" -ForegroundColor White
    Write-Host "Auth Type: $($context.AuthType)" -ForegroundColor White
    Write-Host ""

    # Try a simple API call
    Write-Host "Testing API call..." -ForegroundColor Cyan
    $user = Get-MgUser -Top 1 -ErrorAction Stop | Select-Object -First 1
    Write-Host "API call worked! Retrieved user: $($user.UserPrincipalName)" -ForegroundColor Green
    Write-Host ""

    Write-Host "DIAGNOSIS: Basic auth works fine!" -ForegroundColor Green
    Write-Host "The issue is likely:" -ForegroundColor Yellow
    Write-Host "  - Too many permissions requested at once" -ForegroundColor White
    Write-Host "  - Some permissions require admin approval in your tenant" -ForegroundColor White
    Write-Host "  - Conditional Access policy blocking certain permissions" -ForegroundColor White
    Write-Host ""

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host ""
    Write-Host "FAILED! Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Full error details:" -ForegroundColor Yellow
    Write-Host $_.Exception | Format-List * | Out-String
    Write-Host ""
    Write-Host "DIAGNOSIS: Even basic authentication is broken." -ForegroundColor Red
    Write-Host "Possible causes:" -ForegroundColor Yellow
    Write-Host "  - Conditional Access policy blocking PowerShell" -ForegroundColor White
    Write-Host "  - Network proxy interfering" -ForegroundColor White
    Write-Host "  - Microsoft Graph PowerShell app not available in your tenant" -ForegroundColor White
    Write-Host "  - Your account lacks basic directory read permissions" -ForegroundColor White
    Write-Host ""
}

Write-Host "Press Enter to exit..."
Read-Host

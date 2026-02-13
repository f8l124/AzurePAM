<#
.SYNOPSIS
    Test basic Microsoft Graph authentication

.DESCRIPTION
    Tests Graph connectivity with minimal permissions to diagnose auth issues
#>

Write-Host "`n=== Testing Basic Microsoft Graph Authentication ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Step 1: Testing with basic permissions (User.Read.All)..." -ForegroundColor Yellow
Write-Host "This should work for any Global Reader or Global Admin account." -ForegroundColor Gray
Write-Host ""

try {
    # Disconnect if already connected
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    # Try basic connection
    Connect-MgGraph -Scopes "User.Read.All" -NoWelcome -ErrorAction Stop

    $context = Get-MgContext
    Write-Host "SUCCESS! Connected as: $($context.Account)" -ForegroundColor Green
    Write-Host "Tenant: $($context.TenantId)" -ForegroundColor Green
    Write-Host ""

    # Try to read a user to confirm it works
    Write-Host "Testing API call (Get-MgUser)..." -ForegroundColor Yellow
    $null = Get-MgUser -Top 1 -ErrorAction Stop
    Write-Host "SUCCESS! API calls working." -ForegroundColor Green
    Write-Host ""

    Write-Host "DIAGNOSIS: Authentication works! The issue is likely:" -ForegroundColor Cyan
    Write-Host "  1. Too many permissions requested at once, OR" -ForegroundColor White
    Write-Host "  2. Some permissions require admin consent, OR" -ForegroundColor White
    Write-Host "  3. Your tenant doesn't have required licenses (Premium P2, E5)" -ForegroundColor White
    Write-Host ""

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "DIAGNOSIS: Basic authentication is broken." -ForegroundColor Red
    Write-Host "This suggests a network, proxy, or account issue." -ForegroundColor Red
    Write-Host ""
}

Write-Host "Press Enter to continue..."
Read-Host

# Test using EXACT syntax from error message

Write-Host "Testing with exact syntax from Microsoft's error message..." -ForegroundColor Cyan
Write-Host ""

$scopes = @('Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'Device.Read.All')

Write-Host "Scopes to request:" -ForegroundColor Yellow
$scopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
Write-Host ""

Write-Host "Using: Connect-MgGraph -Audience 'organizations' -Scopes `$scopes -UseDeviceAuthentication" -ForegroundColor Gray
Write-Host ""

try {
    # Use EXACT syntax from error message
    Connect-MgGraph -Audience 'organizations' -Scopes $scopes -UseDeviceAuthentication

    Write-Host ""
    Write-Host "SUCCESS!" -ForegroundColor Green
    $ctx = Get-MgContext
    Write-Host "Tenant: $($ctx.TenantId)" -ForegroundColor White
    Write-Host "Account: $($ctx.Account)" -ForegroundColor White

    Disconnect-MgGraph | Out-Null
}
catch {
    Write-Host ""
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ""
Read-Host "Press Enter to exit"

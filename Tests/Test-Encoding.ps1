# Test if UTF-8 BOM is present
$bytes = Get-Content "Start-EntraChecks.ps1" -Encoding Byte -TotalCount 3
$bom = $bytes -join ','

if ($bom -eq '239,187,191') {
    Write-Host "✓ UTF-8 BOM detected: $bom" -ForegroundColor Green
    Write-Host "File should now parse correctly!" -ForegroundColor Green
} else {
    Write-Host "✗ No UTF-8 BOM found. Got: $bom" -ForegroundColor Red
}

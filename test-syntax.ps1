# Syntax validation script
$files = @(
    ".\Install-Prerequisites.ps1",
    ".\Invoke-EntraChecks.ps1",
    ".\Start-EntraChecks.ps1"
)

$moduleFiles = Get-ChildItem ".\Modules\*.psm1"

Write-Host "`n=== Testing PowerShell Scripts ===" -ForegroundColor Cyan

foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "`nChecking: $file" -ForegroundColor Yellow
        try {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw $file), [ref]$errors)
            if ($errors) {
                Write-Host "  ERRORS FOUND:" -ForegroundColor Red
                foreach ($err in $errors) {
                    Write-Host "    Line $($err.Token.StartLine): $($err.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "  OK - No syntax errors" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "`n=== Testing Module Files ===" -ForegroundColor Cyan

foreach ($file in $moduleFiles) {
    Write-Host "`nChecking: $($file.Name)" -ForegroundColor Yellow
    try {
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw $file.FullName), [ref]$errors)
        if ($errors) {
            Write-Host "  ERRORS FOUND:" -ForegroundColor Red
            foreach ($err in $errors) {
                Write-Host "    Line $($err.Token.StartLine): $($err.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "  OK - No syntax errors" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n=== Validation Complete ===" -ForegroundColor Cyan

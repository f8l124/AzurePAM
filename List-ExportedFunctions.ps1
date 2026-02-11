# List all exported functions from reporting modules
Write-Host "Checking exported functions from each module..." -ForegroundColor Cyan
Write-Host ""

$modules = @(
    'EntraChecks-ComplianceMapping.psm1',
    'EntraChecks-RiskScoring.psm1',
    'EntraChecks-RemediationGuidance.psm1',
    'EntraChecks-HTMLReporting.psm1',
    'EntraChecks-ExcelReporting.psm1'
)

foreach ($moduleName in $modules) {
    $modulePath = ".\Modules\$moduleName"
    Write-Host "$moduleName" -ForegroundColor Yellow

    try {
        Import-Module $modulePath -Force -ErrorAction Stop -WarningAction SilentlyContinue
        $moduleCommands = Get-Command -Module (Get-Module $moduleName.Replace('.psm1', ''))

        if ($moduleCommands.Count -gt 0) {
            foreach ($cmd in $moduleCommands) {
                Write-Host "  - $($cmd.Name)" -ForegroundColor Green
            }
        } else {
            Write-Host "  (No exported functions)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  [ERROR] $_" -ForegroundColor Red
    }

    Write-Host ""
}

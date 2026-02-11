# EntraChecks Reporting - Troubleshooting Guide

Common issues, error messages, and their solutions.

---

## Table of Contents

1. [Connection and Authentication Issues](#connection-and-authentication-issues)
2. [Module Import Errors](#module-import-errors)
3. [Scan and Data Collection Issues](#scan-and-data-collection-issues)
4. [Report Generation Errors](#report-generation-errors)
5. [Performance Issues](#performance-issues)
6. [Common Error Messages](#common-error-messages)
7. [Getting Additional Help](#getting-additional-help)

---

## Connection and Authentication Issues

### Issue: "Insufficient permissions" when connecting

**Error Message:**
```
Insufficient privileges to complete the operation.
```

**Cause:** Your account doesn't have the required Entra ID roles.

**Solution:**
1. Check your current roles:
   ```powershell
   Connect-MgGraph
   $userId = (Get-MgContext).Account
   Get-MgUserMemberOf -UserId $userId | Where-Object {
       $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.directoryRole'
   }
   ```

2. You need ONE of these roles:
   - Global Administrator
   - Global Reader
   - Security Reader

3. Contact your IT administrator to request the appropriate role.

---

### Issue: Browser window doesn't open for authentication

**Error Message:**
```
Unable to open browser for authentication.
```

**Cause:** Windows may be blocking the browser launch, or you're running in a restricted environment.

**Solution Option 1 - Use Device Code Flow:**
```powershell
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All" -UseDeviceCode
```
This will display a code and URL. Open the URL in any browser and enter the code.

**Solution Option 2 - Check Firewall:**
```powershell
# Verify no firewall is blocking PowerShell
Test-NetConnection graph.microsoft.com -Port 443
```

---

### Issue: "The term 'Connect-MgGraph' is not recognized"

**Error Message:**
```
Connect-MgGraph : The term 'Connect-MgGraph' is not recognized as the name of a cmdlet,
function, script file, or operable program.
```

**Cause:** Microsoft.Graph module is not installed.

**Solution:**
```powershell
# Install the module
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Verify installation
Get-Module Microsoft.Graph -ListAvailable

# Import the module
Import-Module Microsoft.Graph
```

---

### Issue: Certificate-based authentication fails (automation scenarios)

**Error Message:**
```
Certificate with thumbprint 'XXXXX' not found in certificate store.
```

**Solution:**
1. Verify certificate is installed:
   ```powershell
   Get-ChildItem Cert:\CurrentUser\My
   Get-ChildItem Cert:\LocalMachine\My
   ```

2. Ensure certificate has the private key:
   ```powershell
   $cert = Get-ChildItem Cert:\LocalMachine\My\$thumbprint
   $cert.HasPrivateKey  # Should be True
   ```

3. Grant permissions to the certificate:
   - Right-click certificate → Manage Private Keys
   - Add the service account running the script
   - Grant Read permission

---

## Module Import Errors

### Issue: "File is blocked" or "Execution policy" errors

**Error Message:**
```
.\Modules\EntraChecks-RiskScoring.psm1 cannot be loaded. The file is not digitally signed.
```
OR
```
Execution of scripts is disabled on this system.
```

**Solution 1 - Unblock files:**
```powershell
# Navigate to EntraChecks folder
Set-Location "C:\Tools\EntraChecks"

# Unblock all PowerShell files
Get-ChildItem -Recurse -Filter *.ps* | Unblock-File

# Verify
Get-ChildItem -Recurse -Filter *.ps* | Get-Item -Stream Zone.Identifier -ErrorAction SilentlyContinue
# Should return nothing if successful
```

**Solution 2 - Set execution policy (temporary):**
```powershell
# For current session only
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Then import modules
Import-Module .\Modules\*.psm1 -Force
```

**Solution 3 - Set execution policy (permanent - requires admin):**
```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned
```

---

### Issue: "Module already loaded" or conflicting versions

**Error Message:**
```
WARNING: The names of some imported commands from the module conflict with names of existing commands.
```

**Solution:**
```powershell
# Remove all loaded modules
Get-Module EntraChecks* | Remove-Module -Force

# Re-import with -Force
Import-Module .\Modules\*.psm1 -Force

# Verify what's loaded
Get-Module EntraChecks*
```

---

### Issue: Module functions not available after import

**Error Message:**
```
The term 'Add-RiskScoring' is not recognized as the name of a cmdlet, function...
```

**Cause:** Module didn't import correctly or functions aren't exported.

**Solution:**
```powershell
# Check if module is loaded
Get-Module EntraChecks-RiskScoring

# If not loaded, import explicitly
Import-Module "C:\Full\Path\To\Modules\EntraChecks-RiskScoring.psm1" -Force -Verbose

# Verify functions are available
Get-Command -Module EntraChecks-RiskScoring

# If still not working, check for syntax errors in the module
Test-ModuleManifest "C:\Full\Path\To\Modules\EntraChecks-RiskScoring.psd1"
```

---

## Scan and Data Collection Issues

### Issue: Scan takes too long or times out

**Symptoms:** Script runs for 10+ minutes or appears to hang.

**Cause:** Large tenant (10,000+ objects) or Graph API throttling.

**Solution:**
```powershell
# Check tenant size
(Get-MgOrganization).DirectorySizeQuota

# For large tenants, use pagination
$PageSize = 100
$users = Get-MgUser -All -PageSize $PageSize

# Monitor throttling
Get-MgContext | Select-Object -ExpandProperty ResponseHeaders
# Look for "Retry-After" header
```

**Prevention:**
- Run scans during off-peak hours
- Implement retry logic with exponential backoff
- Consider splitting scans by category

---

### Issue: "$findings variable is empty" or "No findings returned"

**Cause:** Scan didn't run successfully or you're in a different PowerShell session.

**Solution:**
```powershell
# Verify EntraChecks ran
if (-not $findings) {
    Write-Host "Findings variable not found. Running EntraChecks..." -ForegroundColor Yellow
    .\EntraChecks.ps1
}

# Check if findings were created
$findings.Count
$findings | Select-Object -First 1

# If still empty, check for scan errors
# Review EntraChecks.ps1 output for error messages
```

---

### Issue: "Access denied" for specific checks

**Error Message:**
```
Get-MgConditionalAccessPolicy: Insufficient privileges to complete the operation.
```

**Cause:** Missing specific Graph API permissions.

**Solution:**
```powershell
# Reconnect with all required scopes
Disconnect-MgGraph
Connect-MgGraph -Scopes @(
    "Directory.Read.All",
    "Policy.Read.All",
    "Organization.Read.All",
    "User.Read.All",
    "Group.Read.All",
    "RoleManagement.Read.Directory"
)

# Verify granted permissions
(Get-MgContext).Scopes
```

---

## Report Generation Errors

### Issue: HTML report fails to generate

**Error Message:**
```
Cannot bind argument to parameter 'Findings' because it is null.
```

**Cause:** Findings weren't enhanced or are empty.

**Solution:**
```powershell
# Verify findings exist
if (-not $findings) {
    Write-Host "No findings available. Run EntraChecks first." -ForegroundColor Red
    exit
}

# Verify modules are loaded
Get-Module EntraChecks* | Select-Object Name

# Enhance findings step by step and check for errors
try {
    $step1 = $findings | Add-RiskScoring
    Write-Host "Risk scoring complete: $($step1.Count) findings" -ForegroundColor Green

    $step2 = $step1 | Add-ComplianceMapping
    Write-Host "Compliance mapping complete: $($step2.Count) findings" -ForegroundColor Green

    $step3 = $step2 | Add-RemediationGuidance
    Write-Host "Remediation guidance complete: $($step3.Count) findings" -ForegroundColor Green

    $enhancedFindings = $step3
} catch {
    Write-Host "Error during enhancement: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Yellow
}
```

---

### Issue: Excel report fails - ImportExcel module missing

**Error Message:**
```
The term 'Export-Excel' is not recognized...
```

**Cause:** ImportExcel module not installed.

**Solution Option 1 - Install module:**
```powershell
Install-Module ImportExcel -Scope CurrentUser -Force
Import-Module ImportExcel
```

**Solution Option 2 - Generate without UseImportExcel flag:**
```powershell
# This will create CSV files instead
New-EnhancedExcelReport `
    -Findings $enhancedFindings `
    -OutputPath ".\Report.xlsx" `
    -TenantInfo $tenantInfo
# Will create a folder with CSV files instead
```

---

### Issue: Report file is locked or "Access denied"

**Error Message:**
```
Cannot create file '.\Report.html' because it already exists and is open.
```

**Cause:** File is open in Excel, browser, or another program.

**Solution:**
```powershell
# Close the file in other programs, then:

# Option 1: Use a different filename with timestamp
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$htmlPath = ".\EntraChecks-$timestamp.html"

# Option 2: Remove the existing file
Remove-Item ".\Report.html" -Force -ErrorAction SilentlyContinue

# Option 3: Check what process has the file open (Windows)
$file = "C:\Full\Path\To\Report.html"
$processes = Get-Process | Where-Object {$_.Modules.FileName -eq $file}
$processes | Select-Object Id, ProcessName, Path
# Close those processes, then try again
```

---

### Issue: Report displays garbled text or encoding issues

**Symptoms:** Special characters, emojis, or non-English text appears corrupted.

**Cause:** File encoding mismatch.

**Solution:**
HTML reports should use UTF-8 encoding by default. If issues persist:

```powershell
# For HTML files, ensure they're saved as UTF-8
$htmlContent = Get-Content ".\Report.html" -Raw -Encoding UTF8

# Check current encoding
$encoding = [System.Text.Encoding]::GetEncoding((Get-Content ".\Report.html" -Encoding Byte -TotalCount 4))
$encoding.EncodingName

# If needed, reconvert
$htmlContent = Get-Content ".\Report.html" -Raw
[System.IO.File]::WriteAllText(".\Report-UTF8.html", $htmlContent, [System.Text.Encoding]::UTF8)
```

For browsers:
- Ensure browser is set to UTF-8 encoding (usually automatic)
- Try different browsers (Chrome, Edge, Firefox)

---

## Performance Issues

### Issue: Enhancement pipeline is slow

**Symptoms:** `Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance` takes several minutes.

**Cause:** Processing each finding individually through three modules.

**Solution for small/medium tenants:**
```powershell
# Standard approach (3-5 minutes for 100-200 findings)
$enhancedFindings = $findings |
    Add-RiskScoring |
    Add-ComplianceMapping |
    Add-RemediationGuidance
```

**Solution for large tenants:**
```powershell
# Batch processing (faster for 500+ findings)
$enhancedFindings = @()
$batchSize = 50

for ($i = 0; $i -lt $findings.Count; $i += $batchSize) {
    $end = [Math]::Min($i + $batchSize - 1, $findings.Count - 1)
    $batch = $findings[$i..$end]

    Write-Progress -Activity "Enhancing findings" -Status "$i of $($findings.Count)" -PercentComplete (($i / $findings.Count) * 100)

    $enhancedBatch = $batch |
        Add-RiskScoring |
        Add-ComplianceMapping |
        Add-RemediationGuidance

    $enhancedFindings += $enhancedBatch
}

Write-Progress -Activity "Enhancing findings" -Completed
```

---

### Issue: HTML report is slow to load in browser

**Symptoms:** Browser hangs or takes 30+ seconds to display report.

**Cause:** Too many findings (500+) with all details expanded.

**Solution:**
```powershell
# Option 1: Generate multiple reports by risk level
$critical = $enhancedFindings | Where-Object RiskLevel -eq 'Critical'
$high = $enhancedFindings | Where-Object RiskLevel -eq 'High'

New-EnhancedHTMLReport -Findings $critical -OutputPath ".\Critical.html" -TenantInfo $tenantInfo
New-EnhancedHTMLReport -Findings $high -OutputPath ".\High.html" -TenantInfo $tenantInfo

# Option 2: Filter to top priorities only
$top100 = $enhancedFindings | Sort-Object -Property PriorityScore -Descending | Select-Object -First 100
New-EnhancedHTMLReport -Findings $top100 -OutputPath ".\Top100.html" -TenantInfo $tenantInfo
```

---

## Common Error Messages

### "The property 'RiskScore' cannot be found on this object"

**Full Error:**
```
Add-ComplianceMapping : The property 'RiskScore' cannot be found on this object. Verify that the property exists.
```

**Cause:** Findings weren't passed through `Add-RiskScoring` first.

**Solution:** Always enhance in order:
```powershell
$enhancedFindings = $findings |
    Add-RiskScoring |           # FIRST
    Add-ComplianceMapping |     # SECOND
    Add-RemediationGuidance     # THIRD
```

---

### "Cannot process argument because the value of argument 'path' is null"

**Cause:** OutputPath parameter is empty or invalid.

**Solution:**
```powershell
# Ensure path is valid
$outputPath = ".\Report.html"
if (-not (Test-Path (Split-Path $outputPath -Parent))) {
    New-Item -Path (Split-Path $outputPath -Parent) -ItemType Directory
}

# Use absolute path
$outputPath = Join-Path (Get-Location) "Report.html"
$outputPath = [System.IO.Path]::GetFullPath($outputPath)
```

---

### "You must call the Connect-MgGraph cmdlet before calling any other cmdlets"

**Cause:** Not connected to Microsoft Graph.

**Solution:**
```powershell
# Check connection status
Get-MgContext

# If null, connect
if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "Organization.Read.All"
}
```

---

### "Invoke-MgGraphRequest : Resource 'XXX' does not exist"

**Cause:** API endpoint doesn't exist or tenant configuration is unusual.

**Solution:**
```powershell
# Check Graph API endpoint availability
$testUri = "https://graph.microsoft.com/v1.0/organization"
Invoke-MgGraphRequest -Uri $testUri -Method GET

# Verify tenant ID is correct
(Get-MgContext).TenantId
(Get-MgOrganization).Id

# Check Graph API profile
Select-MgProfile -Name "v1.0"  # or "beta"
```

---

### Memory errors with large datasets

**Error:**
```
Out of memory exception
```

**Cause:** Processing too many findings at once.

**Solution:**
```powershell
# Clear variables regularly
Remove-Variable findings, enhancedFindings -ErrorAction SilentlyContinue

# Force garbage collection
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

# Process in smaller batches (see Performance Issues section)
```

---

## Getting Additional Help

### Enable Verbose Logging

```powershell
# For module imports
Import-Module .\Modules\*.psm1 -Force -Verbose

# For Graph commands
Get-MgUser -UserId "user@domain.com" -Verbose

# For report generation
$VerbosePreference = "Continue"
New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath ".\Report.html" -TenantInfo $tenantInfo -Verbose
```

### Capture Full Error Details

```powershell
# Get detailed error information
$Error[0] | Format-List -Force

# Get stack trace
$Error[0].ScriptStackTrace

# Get inner exception
$Error[0].Exception.InnerException

# Export all errors to file
$Error | Export-Clixml ".\errors.xml"
```

### Test Individual Components

```powershell
# Test a single finding through the pipeline
$testFinding = $findings | Select-Object -First 1

Write-Host "Testing risk scoring..." -ForegroundColor Cyan
$testFinding | Add-RiskScoring | Format-List

Write-Host "Testing compliance mapping..." -ForegroundColor Cyan
$testFinding | Add-RiskScoring | Add-ComplianceMapping | Format-List

Write-Host "Testing remediation guidance..." -ForegroundColor Cyan
$testFinding | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance | Format-List
```

### Verify Module Health

```powershell
# Check module versions and status
Get-Module EntraChecks* | Select-Object Name, Version, Path

# Reload a specific module
Remove-Module EntraChecks-RiskScoring -Force
Import-Module .\Modules\EntraChecks-RiskScoring.psm1 -Force -Verbose

# Test module functions individually
Get-Command -Module EntraChecks-RiskScoring | ForEach-Object {
    Write-Host "Testing $($_.Name)..." -ForegroundColor Cyan
    Get-Help $_.Name -Examples
}
```

---

## Still Having Issues?

### Checklist Before Seeking Help

- [ ] PowerShell version 5.1 or higher: `$PSVersionTable.PSVersion`
- [ ] Microsoft.Graph module installed: `Get-Module Microsoft.Graph -ListAvailable`
- [ ] ImportExcel module installed (for Excel): `Get-Module ImportExcel -ListAvailable`
- [ ] Files unblocked: `Get-ChildItem *.ps* | Get-Item -Stream Zone.Identifier -EA SilentlyContinue`
- [ ] Connected to Graph: `Get-MgContext`
- [ ] Appropriate permissions: Reviewed [Connection Issues](#connection-and-authentication-issues)
- [ ] Modules imported: `Get-Module EntraChecks*`
- [ ] Findings exist: `$findings.Count`
- [ ] Error details captured: `$Error[0] | Format-List -Force`

### Information to Provide When Seeking Help

1. **Environment:**
   - PowerShell version
   - Operating system
   - Module versions

2. **Error Information:**
   - Full error message
   - Stack trace
   - What you were trying to do

3. **Steps to Reproduce:**
   - Exact commands you ran
   - What worked vs what didn't

4. **Configuration:**
   - Tenant size
   - Number of findings
   - Custom modifications

---

**Related Documentation:**
- [GETTING-STARTED.md](GETTING-STARTED.md) - Beginner's tutorial
- [USER-GUIDE.md](USER-GUIDE.md) - Comprehensive documentation
- [EXAMPLES.md](EXAMPLES.md) - Usage examples
- [API-REFERENCE.md](API-REFERENCE.md) - Function reference

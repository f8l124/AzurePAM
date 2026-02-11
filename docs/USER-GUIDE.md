# EntraChecks Reporting Modules - Complete User Guide

**Version:** 1.0.0
**Last Updated:** 2026-02-10
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Module Reference](#module-reference)
5. [Usage Patterns](#usage-patterns)
6. [Report Types](#report-types)
7. [Customization](#customization)
8. [Automation](#automation)
9. [Best Practices](#best-practices)
10. [Performance Tuning](#performance-tuning)

---

## Overview

### What are the EntraChecks Reporting Modules?

The EntraChecks Reporting Modules are a suite of five PowerShell modules that enhance security assessment findings with:

- **Risk scoring and prioritization**
- **Compliance framework mappings** (CIS M365, NIST CSF, SOC2, PCI-DSS)
- **Detailed remediation guidance** with step-by-step instructions
- **Professional HTML reports** with interactive dashboards
- **Multi-sheet Excel workbooks** with charts and analytics

### Key Features

✅ **Risk-Based Prioritization** - Automatically calculates risk scores (0-100) based on severity, scope, and exploitability
✅ **ROI Analysis** - Identifies "quick wins" with high security impact and low implementation effort
✅ **Compliance Ready** - Maps findings to 100+ compliance controls across major frameworks
✅ **Actionable Guidance** - Provides Azure Portal steps AND PowerShell automation commands
✅ **Executive-Ready Reports** - Professional dashboards suitable for board presentations
✅ **Zero Dependencies** - HTML reports work in any browser, no special software required

---

## Architecture

### Module Dependencies

```
EntraChecks.ps1 (main script)
      │
      ├─> Findings (raw data)
      │
      ▼
┌─────────────────────────────────────────┐
│  Enhancement Pipeline                    │
├─────────────────────────────────────────┤
│  1. ComplianceMapping.psm1              │
│     └─> Adds framework mappings         │
│                                          │
│  2. RiskScoring.psm1                    │
│     └─> Calculates risk scores         │
│                                          │
│  3. RemediationGuidance.psm1            │
│     └─> Adds fix instructions           │
└─────────────────────────────────────────┘
      │
      ▼
Enhanced Findings
      │
      ├─> HTMLReporting.psm1 ──> Interactive HTML Report
      │
      └─> ExcelReporting.psm1 ──> Multi-sheet Excel Workbook
```

### Data Flow

1. **Input:** Raw findings from EntraChecks.ps1
2. **Enhancement:** Findings enriched with metadata
3. **Analysis:** Risk summaries and prioritization
4. **Output:** HTML and/or Excel reports

---

## Installation

### Prerequisites

**Required:**
- Windows PowerShell 5.1+ or PowerShell Core 7+
- Microsoft.Graph PowerShell module
- Appropriate Entra ID permissions (Global Reader or Security Reader)

**Optional:**
- ImportExcel module (for Excel report generation)
- Microsoft Excel (for viewing Excel reports - not required to create them)

### Installation Steps

#### 1. Install Microsoft Graph PowerShell

```powershell
# Install for current user (no admin rights needed)
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# OR install for all users (requires admin)
Install-Module Microsoft.Graph -Force

# Verify installation
Get-Module Microsoft.Graph -ListAvailable
```

#### 2. Install ImportExcel (Optional)

```powershell
# Install for current user
Install-Module ImportExcel -Scope CurrentUser -Force

# Verify installation
Get-Module ImportExcel -ListAvailable
```

#### 3. Download EntraChecks

Download and extract the EntraChecks package to a local folder, for example:
```
C:\Tools\EntraChecks\
```

#### 4. Unblock Files (Important!)

Windows may block downloaded PowerShell files. Unblock them:

```powershell
# Navigate to the EntraChecks folder
Set-Location "C:\Tools\EntraChecks"

# Unblock all PowerShell files
Get-ChildItem -Recurse -Filter *.ps* | Unblock-File
```

#### 5. Verify Installation

```powershell
# Import all modules
Import-Module .\Modules\EntraChecks-ComplianceMapping.psm1
Import-Module .\Modules\EntraChecks-RiskScoring.psm1
Import-Module .\Modules\EntraChecks-RemediationGuidance.psm1
Import-Module .\Modules\EntraChecks-HTMLReporting.psm1
Import-Module .\Modules\EntraChecks-ExcelReporting.psm1

# Check available functions
Get-Command -Module EntraChecks*

# You should see 23 exported functions
```

---

## Module Reference

### 1. EntraChecks-ComplianceMapping.psm1

Maps findings to compliance framework controls.

**Exported Functions:**
- `Get-ComplianceMapping` - Get mappings for a specific finding type
- `Add-ComplianceMapping` - Add compliance data to finding objects
- `Get-ComplianceGapReport` - Generate compliance gap analysis
- `Get-FindingsForControl` - Find all findings affecting a control
- `Get-AllComplianceMappings` - List all available mappings
- `Format-ComplianceReference` - Format compliance references for display

**Supported Frameworks:**
- CIS Microsoft 365 Foundations Benchmark
- NIST Cybersecurity Framework (CSF)
- SOC 2 Trust Service Criteria
- PCI-DSS v4.0

**Example:**
```powershell
# Get compliance mapping for MFA finding
$mapping = Get-ComplianceMapping -FindingType "MFA_Disabled" -Framework "CIS_M365"

# Add mappings to all findings
$findings = $findings | Add-ComplianceMapping

# Generate gap report
$gapReport = Get-ComplianceGapReport -Findings $findings -Framework "All"
```

---

### 2. EntraChecks-RiskScoring.psm1

Calculates risk scores and prioritizes findings.

**Exported Functions:**
- `Calculate-RiskScore` - Calculate risk score for a finding (0-100)
- `Get-RiskLevel` - Get risk level (Critical/High/Medium/Low)
- `Add-RiskScoring` - Add risk scoring to finding objects
- `Get-RiskSummary` - Generate risk statistics summary
- `Get-PrioritizedFindings` - Get findings sorted by priority
- `Get-QuickWins` - Identify high-impact, low-effort fixes
- `Format-PriorityRecommendation` - Format priority recommendations

**Risk Calculation Factors:**
- **Base Risk** - Severity of the vulnerability (by finding type)
- **Scope Multiplier** - Number of users/resources affected
- **Sensitivity Multiplier** - Data classification level
- **Exploitability** - Ease of exploitation
- **Compliance Impact** - Number of frameworks affected

**Risk Levels:**
- **Critical (90-100):** Immediate action required
- **High (70-89):** Fix within 1 week
- **Medium (40-69):** Fix within 1 month
- **Low (0-39):** Fix when convenient

**Example:**
```powershell
# Add risk scoring to findings
$findings = $findings | Add-RiskScoring

# Get risk summary statistics
$riskSummary = Get-RiskSummary -Findings $findings

# Display critical findings
$critical = $findings | Where-Object { $_.RiskLevel -eq 'Critical' }

# Get prioritized list (by risk/effort ratio)
$prioritized = Get-PrioritizedFindings -Findings $findings

# Get quick wins (high ROI)
$quickWins = Get-QuickWins -Findings $findings
```

---

### 3. EntraChecks-RemediationGuidance.psm1

Provides detailed fix instructions for findings.

**Exported Functions:**
- `Get-RemediationGuidance` - Get detailed guidance for a finding type
- `Add-RemediationGuidance` - Add remediation data to finding objects
- `Format-RemediationSteps` - Format guidance for different outputs (Text/HTML/Markdown)

**Guidance Includes:**
- **Title** - Clear description of the fix
- **Summary** - Brief overview
- **Impact Analysis** - Positive and negative effects
- **Prerequisites** - Required roles and tools
- **Azure Portal Steps** - Click-by-click instructions
- **PowerShell Commands** - Automated fix scripts
- **Verification Steps** - How to confirm the fix worked
- **Rollback Procedures** - How to undo changes if needed
- **Common Issues** - Troubleshooting tips
- **References** - Microsoft documentation links

**Example:**
```powershell
# Get guidance for a specific issue
$guidance = Get-RemediationGuidance -FindingType "MFA_Disabled"

# Add guidance to all findings
$findings = $findings | Add-RemediationGuidance

# Format guidance as HTML
$html = Format-RemediationSteps -Guidance $guidance -Format "HTML"

# Format guidance as Markdown
$markdown = Format-RemediationSteps -Guidance $guidance -Format "Markdown"
```

---

### 4. EntraChecks-HTMLReporting.psm1

Generates interactive HTML reports with dashboards.

**Exported Functions:**
- `New-EnhancedHTMLReport` - Generate complete HTML report

**Report Sections:**
1. **Header** - Tenant information and scan metadata
2. **Executive Dashboard** - High-level KPIs and metrics
3. **Quick Wins** - Top 5 easy, high-impact fixes
4. **Priority Findings** - Top 25 findings by priority score
5. **Compliance Framework Mapping** - Framework-specific views
6. **Detailed Findings** - All findings with full remediation steps

**Interactive Features:**
- **Collapsible findings** - Click to expand/collapse details
- **Search** - Real-time search across all findings
- **Risk level filtering** - Filter by Critical/High/Medium/Low
- **Smooth navigation** - Click navigation menu to jump to sections
- **Responsive design** - Works on desktop, tablet, and mobile

**Example:**
```powershell
# Basic usage
New-EnhancedHTMLReport `
    -Findings $enhancedFindings `
    -OutputPath ".\Report.html" `
    -TenantInfo $tenantInfo

# With custom output location
$outputPath = "C:\Reports\Entra-$(Get-Date -Format 'yyyy-MM-dd').html"
New-EnhancedHTMLReport `
    -Findings $enhancedFindings `
    -OutputPath $outputPath `
    -TenantInfo $tenantInfo

# Open automatically in browser
Start-Process $outputPath
```

---

### 5. EntraChecks-ExcelReporting.psm1

Generates multi-sheet Excel workbooks with analytics.

**Exported Functions:**
- `New-EnhancedExcelReport` - Generate complete Excel workbook

**Excel Sheets:**
1. **Executive Summary** - Key metrics table
2. **All Findings** - Complete findings list (filterable)
3. **Priority Findings** - Top 25 by priority score
4. **Quick Wins** - High ROI fixes
5. **Compliance - CIS M365** - CIS-mapped findings
6. **Compliance - NIST CSF** - NIST-mapped findings
7. **Compliance - SOC2** - SOC2-mapped findings
8. **Compliance - PCI-DSS** - PCI-DSS-mapped findings
9. **Risk Analysis** - Statistical breakdown

**Excel Features:**
- **Auto-sized columns** - Perfect width for readability
- **Frozen headers** - Headers stay visible when scrolling
- **Bold headers** - Easy to distinguish headers from data
- **Auto-filters** - Filter and sort any column
- **Formatted data** - Percentages, dates, and numbers properly formatted

**Example:**
```powershell
# With ImportExcel module
New-EnhancedExcelReport `
    -Findings $enhancedFindings `
    -OutputPath ".\Report.xlsx" `
    -TenantInfo $tenantInfo `
    -UseImportExcel

# Without ImportExcel (falls back to CSV)
New-EnhancedExcelReport `
    -Findings $enhancedFindings `
    -OutputPath ".\Report.xlsx" `
    -TenantInfo $tenantInfo
# This will create CSV files instead in a folder
```

---

## Usage Patterns

### Basic Workflow

```powershell
# 1. Navigate to EntraChecks folder
Set-Location "C:\Tools\EntraChecks"

# 2. Connect to Entra ID
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "Organization.Read.All"

# 3. Run scan
.\EntraChecks.ps1
# Results are stored in $findings variable

# 4. Import reporting modules
Import-Module .\Modules\*.psm1 -Force

# 5. Get tenant information
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

# 6. Enhance findings
$enhancedFindings = $findings |
    Add-RiskScoring |
    Add-ComplianceMapping |
    Add-RemediationGuidance

# 7. Generate reports
New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath ".\Report.html" -TenantInfo $tenantInfo
New-EnhancedExcelReport -Findings $enhancedFindings -OutputPath ".\Report.xlsx" -TenantInfo $tenantInfo -UseImportExcel

# 8. Disconnect
Disconnect-MgGraph
```

---

### Advanced: Filtering and Custom Reports

```powershell
# Get only Critical and High risk findings
$highRiskFindings = $enhancedFindings | Where-Object {
    $_.RiskLevel -in @('Critical', 'High')
}

# Generate report for high risk items only
New-EnhancedHTMLReport `
    -Findings $highRiskFindings `
    -OutputPath ".\HighRisk-Report.html" `
    -TenantInfo $tenantInfo

# Get findings for a specific compliance framework
$cisFindings = $enhancedFindings | Where-Object {
    $_.ComplianceMappings.CIS_M365
}

# Get findings by category
$mfaFindings = $enhancedFindings | Where-Object {
    $_.Type -like "*MFA*"
}

# Get quick wins only
$quickWins = Get-QuickWins -Findings $enhancedFindings
New-EnhancedHTMLReport `
    -Findings $quickWins `
    -OutputPath ".\QuickWins-Report.html" `
    -TenantInfo $tenantInfo
```

---

### Advanced: Custom Risk Thresholds

```powershell
# Define custom quick win criteria
$customQuickWins = $enhancedFindings | Where-Object {
    $_.RiskScore -ge 60 -and  # Medium to High risk
    $_.RemediationEffort -le 3  # Low to Medium effort
} | Sort-Object -Property PriorityScore -Descending

# Filter by remediation effort
$easyFixes = $enhancedFindings | Where-Object {
    $_.RemediationEffortDescription -in @('Low', 'Very Low')
}

# Filter by number of users affected
$widespreadIssues = $enhancedFindings | Where-Object {
    $_.AffectedCount -gt 100
}
```

---

## Report Types

### HTML Reports

**Best for:**
- Executive presentations
- Sharing with non-technical stakeholders
- Interactive exploration of findings
- No special software requirements

**Advantages:**
- ✅ Works in any web browser
- ✅ Mobile-friendly responsive design
- ✅ Interactive (search, filter, collapse/expand)
- ✅ No software installation required
- ✅ Easy to share via email or SharePoint

**File Size:** Typically 200-500 KB for 50-100 findings

---

### Excel Reports

**Best for:**
- Detailed analysis and data manipulation
- Tracking remediation progress over time
- Creating custom charts and pivots
- Audit documentation

**Advantages:**
- ✅ Full Excel functionality (sort, filter, pivot)
- ✅ Easy to add notes and tracking columns
- ✅ Can import into databases or BI tools
- ✅ Familiar format for business users
- ✅ Multiple sheets for organized data

**File Size:** Typically 50-150 KB for 50-100 findings

---

## Customization

### Customizing Risk Scoring

To adjust risk scoring factors, edit `EntraChecks-RiskScoring.psm1`:

```powershell
# Risk score thresholds (line ~30)
$Script:RiskThresholds = @{
    Critical = 90  # Change to adjust Critical threshold
    High     = 70  # Change to adjust High threshold
    Medium   = 40  # Change to adjust Medium threshold
    Low      = 0
}

# Impact factor multipliers (line ~45)
$Script:ImpactFactors = @{
    'Global'     = 1.5   # Tenant-wide impact
    'High'       = 1.3   # High impact
    'Medium'     = 1.1   # Medium impact
    'Low'        = 1.0   # Low impact
}
```

### Adding Custom Compliance Frameworks

To add a new framework, edit `EntraChecks-ComplianceMapping.psm1`:

```powershell
# Add to the $Script:ComplianceMappings hashtable (around line 30)
'YOUR_FRAMEWORK_NAME' = @{
    'YourFindingType' = @{
        Controls    = @('Control-1.1', 'Control-2.3')
        Title       = 'Control Title'
        Description = 'What this control requires'
    }
}
```

### Adding Custom Remediation Guidance

To add guidance for a new finding type, edit `EntraChecks-RemediationGuidance.psm1`:

```powershell
# Add to the $Script:RemediationGuidance hashtable (around line 25)
'YourFindingType' = @{
    Title           = 'Fix Title'
    Summary         = 'Brief description'
    Impact          = @{
        Positive = 'Benefits of fixing'
        Negative = 'Potential drawbacks or considerations'
    }
    Prerequisites   = @(
        'Required role or permission'
        'Required tools or software'
    )
    StepsPortal     = @(
        '1. Navigate to...'
        '2. Click on...'
        '3. Configure...'
    )
    StepsPowerShell = @'
# PowerShell commands to automate the fix
Connect-MgGraph
# ... your commands here
'@
    Verification    = @(
        'How to verify the fix worked'
    )
    Rollback        = @(
        'How to undo the change if needed'
    )
    CommonIssues    = @(
        'Issue: Problem | Solution: How to fix it'
    )
    References      = @(
        'https://learn.microsoft.com/...'
    )
}
```

---

## Automation

### Scheduled Assessment Script

Create a script that runs automatically on a schedule:

```powershell
# SavedScript: Run-EntraChecksScheduled.ps1

#Requires -Modules Microsoft.Graph

# Configuration
$EntraChecksPath = "C:\Tools\EntraChecks"
$OutputPath = "C:\Reports\EntraChecks"
$TenantId = "your-tenant-id-here"

# Create output folder if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory | Out-Null
}

# Connect to Microsoft Graph (using certificate or app credentials)
# Option 1: Certificate-based authentication (recommended for automation)
Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertThumbprint

# Option 2: Client secret (less secure, not recommended for production)
# $SecureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
# $ClientSecretCredential = New-Object System.Management.Automation.PSCredential($ClientId, $SecureSecret)
# Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential

# Change to EntraChecks directory
Set-Location $EntraChecksPath

# Run the assessment
.\EntraChecks.ps1

# Import reporting modules
Import-Module .\Modules\*.psm1 -Force

# Get tenant info
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

# Enhance findings
$enhancedFindings = $findings |
    Add-RiskScoring |
    Add-ComplianceMapping |
    Add-RemediationGuidance

# Generate timestamped reports
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$htmlPath = Join-Path $OutputPath "EntraChecks-$timestamp.html"
$excelPath = Join-Path $OutputPath "EntraChecks-$timestamp.xlsx"

New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath $htmlPath -TenantInfo $tenantInfo
New-EnhancedExcelReport -Findings $enhancedFindings -OutputPath $excelPath -TenantInfo $tenantInfo -UseImportExcel

# Send email notification (optional)
$mailParams = @{
    To          = "security-team@yourdomain.com"
    From        = "entrachecks@yourdomain.com"
    Subject     = "EntraChecks Monthly Report - $($tenantInfo.TenantName)"
    Body        = "Please find attached the latest EntraChecks security assessment report."
    Attachments = @($htmlPath, $excelPath)
    SmtpServer  = "smtp.yourdomain.com"
}
Send-MailMessage @mailParams

# Disconnect
Disconnect-MgGraph

# Log completion
Write-Host "Assessment completed at $(Get-Date)" | Out-File -Append "$OutputPath\assessment-log.txt"
```

### Create Windows Scheduled Task

```powershell
# Run as Administrator

$action = New-ScheduledTaskAction `
    -Execute 'PowerShell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Run-EntraChecksScheduled.ps1"'

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am

$principal = New-ScheduledTaskPrincipal `
    -UserId "DOMAIN\ServiceAccount" `
    -LogonType Password `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName "EntraChecks Monthly Assessment" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "Runs EntraChecks security assessment monthly"
```

---

## Best Practices

### Security

1. **Use Least Privilege**
   - Assign Global Reader or Security Reader role (not Global Administrator)
   - Use dedicated service accounts for automation
   - Use certificate-based authentication for scheduled tasks

2. **Protect Credentials**
   - Never hardcode passwords in scripts
   - Use Windows Credential Manager or Azure Key Vault
   - Rotate service account credentials regularly

3. **Secure Reports**
   - Reports may contain sensitive security information
   - Store reports in secure locations (SharePoint with permissions)
   - Consider encrypting reports for email transmission
   - Set appropriate retention policies

### Performance

1. **Module Loading**
   - Import modules once at the start of your session
   - Use `-Force` only when necessary (reloads module)
   - Consider using `$PSModuleAutoLoadingPreference` for large scripts

2. **Large Tenants**
   - For tenants with 10,000+ objects, expect 5-10 minute scan times
   - Run during off-hours to avoid Graph API throttling
   - Consider breaking up scans by category if needed

3. **Report Generation**
   - HTML reports are faster to generate than Excel (10-30 seconds vs 1-3 minutes)
   - Excel performance depends on ImportExcel module version
   - Large reports (500+ findings) may take several minutes

### Operational

1. **Regular Assessments**
   - Run monthly minimum, weekly recommended
   - Run after major configuration changes
   - Track trends over time

2. **Remediation Tracking**
   - Use Excel reports to track remediation progress
   - Add columns for "Assigned To", "Due Date", "Status"
   - Re-scan to verify fixes

3. **Version Control**
   - Keep EntraChecks in a version-controlled repository
   - Track changes to custom configurations
   - Document any modifications made to modules

4. **Documentation**
   - Document your specific environment considerations
   - Keep notes on custom mappings or risk thresholds
   - Share tribal knowledge with team

---

## Performance Tuning

### Optimizing Scan Time

```powershell
# Run only specific checks (if EntraChecks supports it)
.\EntraChecks.ps1 -CheckTypes @('MFA', 'ConditionalAccess')

# Use pagination for large tenants
$allUsers = Get-MgUser -All -PageSize 100

# Cache tenant information
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}
# Reuse $tenantInfo variable instead of calling Get-MgOrganization repeatedly
```

### Optimizing Report Generation

```powershell
# Generate only the reports you need
# HTML only (faster)
New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath ".\Report.html" -TenantInfo $tenantInfo

# For large finding sets, consider filtering first
if ($enhancedFindings.Count -gt 200) {
    # Generate separate reports by risk level
    $criticalFindings = $enhancedFindings | Where-Object { $_.RiskLevel -eq 'Critical' }
    New-EnhancedHTMLReport -Findings $criticalFindings -OutputPath ".\Critical.html" -TenantInfo $tenantInfo

    $highFindings = $enhancedFindings | Where-Object { $_.RiskLevel -eq 'High' }
    New-EnhancedHTMLReport -Findings $highFindings -OutputPath ".\High.html" -TenantInfo $tenantInfo
}
```

### Memory Management

```powershell
# For very large tenants, process findings in batches
$batchSize = 100
for ($i = 0; $i -lt $findings.Count; $i += $batchSize) {
    $batch = $findings[$i..([Math]::Min($i + $batchSize - 1, $findings.Count - 1))]
    $enhancedBatch = $batch |
        Add-RiskScoring |
        Add-ComplianceMapping |
        Add-RemediationGuidance
    $enhancedFindings += $enhancedBatch
}

# Clear variables when done
Remove-Variable findings, enhancedFindings -ErrorAction SilentlyContinue
[System.GC]::Collect()
```

---

## Additional Resources

- **Getting Started:** [GETTING-STARTED.md](GETTING-STARTED.md) - Beginner's tutorial
- **Examples:** [EXAMPLES.md](EXAMPLES.md) - Real-world usage examples
- **API Reference:** [API-REFERENCE.md](API-REFERENCE.md) - Detailed function reference
- **Troubleshooting:** [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions
- **Status Report:** [REPORTING-STATUS.md](REPORTING-STATUS.md) - Current module status

---

## Support

For issues, questions, or contributions:
- Check the documentation files listed above
- Review common issues in TROUBLESHOOTING.md
- Search Microsoft documentation for Entra ID specifics

---

**Last Updated:** 2026-02-10
**Module Version:** 1.0.0
**Status:** Production Ready ✅

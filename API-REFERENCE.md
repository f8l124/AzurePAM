# EntraChecks Reporting Modules - API Reference

Complete function reference documentation.

---

## Table of Contents

1. [Compliance Mapping Functions](#compliance-mapping-functions)
2. [Risk Scoring Functions](#risk-scoring-functions)
3. [Remediation Guidance Functions](#remediation-guidance-functions)
4. [HTML Reporting Functions](#html-reporting-functions)
5. [Excel Reporting Functions](#excel-reporting-functions)

---

## Compliance Mapping Functions

### Get-ComplianceMapping

Gets compliance framework mappings for a specific finding type.

**Module:** EntraChecks-ComplianceMapping.psm1

**Syntax:**
```powershell
Get-ComplianceMapping
    -FindingType <String>
    [-Framework <String>]
    [<CommonParameters>]
```

**Parameters:**
- `-FindingType` (String, Mandatory)
  - The type of finding to get mappings for
  - Example: `"MFA_Disabled"`, `"LegacyAuth_Enabled"`

- `-Framework` (String, Optional)
  - Specific framework to filter by
  - Valid values: `"CIS_M365"`, `"NIST_CSF"`, `"SOC2"`, `"PCI_DSS_4"`, `"All"`
  - Default: `"All"`

**Returns:**
- `[Hashtable]` - Compliance mappings for the finding type
  - Keys: Framework names (`CIS_M365`, `NIST_CSF`, `SOC2`, `PCI_DSS_4`)
  - Values: Hashtables with `Controls`, `Title`, `Description`

**Example:**
```powershell
# Get all mappings for MFA findings
$mappings = Get-ComplianceMapping -FindingType "MFA_Disabled"

# Get only CIS mappings
$cisMappings = Get-ComplianceMapping -FindingType "MFA_Disabled" -Framework "CIS_M365"

# Display CIS controls
$cisMappings.CIS_M365.Controls
# Output: @('1.1.1', '6.1.1')
```

---

### Add-ComplianceMapping

Adds compliance mapping data to finding objects.

**Module:** EntraChecks-ComplianceMapping.psm1

**Syntax:**
```powershell
Add-ComplianceMapping
    -Finding <Object>
    [<CommonParameters>]
```

**Parameters:**
- `-Finding` (Object, Mandatory, ValueFromPipeline)
  - The finding object to enhance
  - Must have `Type`, `CheckType`, or `Category` property

**Returns:**
- `[PSCustomObject]` - Finding with added `ComplianceMappings` property
  - `ComplianceMappings` - Hashtable with framework mappings
  - `ComplianceReference` - Formatted string of all mappings

**Example:**
```powershell
# Single finding
$enhancedFinding = $finding | Add-ComplianceMapping

# Multiple findings
$enhancedFindings = $findings | Add-ComplianceMapping

# Check added properties
$enhancedFinding.ComplianceMappings.CIS_M365
$enhancedFinding.ComplianceReference
# Output: "CIS M365: 1.1.1, 6.1.1; NIST CSF: ID.AM-6, PR.AC-7"
```

---

### Get-ComplianceGapReport

Generates a compliance gap analysis report.

**Module:** EntraChecks-ComplianceMapping.psm1

**Syntax:**
```powershell
Get-ComplianceGapReport
    -Findings <Array>
    [-Framework <String>]
    [<CommonParameters>]
```

**Parameters:**
- `-Findings` (Array, Mandatory)
  - Array of findings (must be enhanced with compliance mappings)

- `-Framework` (String, Optional)
  - Framework to analyze
  - Valid values: `"CIS"`, `"NIST"`, `"SOC2"`, `"PCIDSS"`, `"All"`
  - Default: `"All"`

**Returns:**
- `[PSCustomObject]` - Gap analysis with properties:
  - `TotalFindings` - Number of findings
  - `FrameworkGaps` - Hashtable with per-framework statistics:
    - `ControlsAffected` - Number of controls with findings
    - `TotalControls` - Total controls in framework
    - `TopControls` - Most affected controls
    - `CriticalGaps` - High-risk gaps

**Example:**
```powershell
# Get gap report for all frameworks
$gapReport = Get-ComplianceGapReport -Findings $enhancedFindings

# Access CIS data
$gapReport.FrameworkGaps.CIS.ControlsAffected
$gapReport.FrameworkGaps.CIS.TotalControls

# Calculate compliance percentage
$complianceRate = 1 - ($gapReport.FrameworkGaps.CIS.ControlsAffected / $gapReport.FrameworkGaps.CIS.TotalControls)
Write-Host "CIS Compliance: $([Math]::Round($complianceRate * 100, 1))%"
```

---

### Get-FindingsForControl

Gets all findings that affect a specific compliance control.

**Module:** EntraChecks-ComplianceMapping.psm1

**Syntax:**
```powershell
Get-FindingsForControl
    -Findings <Array>
    -Framework <String>
    -Control <String>
    [<CommonParameters>]
```

**Parameters:**
- `-Findings` (Array, Mandatory)
  - Array of findings to search

- `-Framework` (String, Mandatory)
  - Framework name (`"CIS_M365"`, `"NIST_CSF"`, `"SOC2"`, `"PCI_DSS_4"`)

- `-Control` (String, Mandatory)
  - Control identifier (e.g., `"1.1.1"`, `"PR.AC-7"`)

**Returns:**
- `[Array]` - Findings affecting the specified control

**Example:**
```powershell
# Get all findings affecting CIS control 1.1.1
$cisFindings = Get-FindingsForControl `
    -Findings $enhancedFindings `
    -Framework "CIS_M365" `
    -Control "1.1.1"

# Display findings
$cisFindings | Select-Object Description, RiskLevel
```

---

### Get-AllComplianceMappings

Retrieves all available compliance mappings.

**Module:** EntraChecks-ComplianceMapping.psm1

**Syntax:**
```powershell
Get-AllComplianceMappings
    [<CommonParameters>]
```

**Parameters:** None

**Returns:**
- `[Hashtable]` - All compliance mappings
  - Keys: Finding types
  - Values: Framework mappings

**Example:**
```powershell
$allMappings = Get-AllComplianceMappings

# List all mapped finding types
$allMappings.Keys

# Get all CIS-mapped finding types
$allMappings.Keys | Where-Object {
    $allMappings[$_].CIS_M365
}
```

---

### Format-ComplianceReference

Formats compliance references for display.

**Module:** EntraChecks-ComplianceMapping.psm1

**Syntax:**
```powershell
Format-ComplianceReference
    -Mappings <Hashtable>
    [-Format <String>]
    [<CommonParameters>]
```

**Parameters:**
- `-Mappings` (Hashtable, Mandatory)
  - Compliance mappings hashtable

- `-Format` (String, Optional)
  - Output format
  - Valid values: `"Text"`, `"HTML"`, `"Markdown"`
  - Default: `"Text"`

**Returns:**
- `[String]` - Formatted compliance reference

**Example:**
```powershell
$mappings = Get-ComplianceMapping -FindingType "MFA_Disabled"

# Text format (default)
Format-ComplianceReference -Mappings $mappings
# Output: "CIS M365: 1.1.1, 6.1.1; NIST CSF: ID.AM-6; SOC2: CC6.1"

# HTML format
Format-ComplianceReference -Mappings $mappings -Format "HTML"
# Output: "<span class='framework'>CIS M365</span>: 1.1.1, 6.1.1; ..."

# Markdown format
Format-ComplianceReference -Mappings $mappings -Format "Markdown"
# Output: "**CIS M365:** 1.1.1, 6.1.1; **NIST CSF:** ID.AM-6; ..."
```

---

## Risk Scoring Functions

### Calculate-RiskScore

Calculates a risk score (0-100) for a finding.

**Module:** EntraChecks-RiskScoring.psm1

**Syntax:**
```powershell
Calculate-RiskScore
    -Finding <Object>
    [<CommonParameters>]
```

**Parameters:**
- `-Finding` (Object, Mandatory)
  - Finding object with `Type`, `Scope`, `DataSensitivity`, `Exploitability` properties

**Returns:**
- `[Int]` - Risk score from 0-100

**Scoring Factors:**
- **Base Risk:** Finding type severity (30-80 points)
- **Scope Multiplier:** 1.0-1.5x (based on affected users/resources)
- **Sensitivity Multiplier:** 1.0-1.3x (based on data classification)
- **Exploitability Multiplier:** 0.9-1.3x (ease of exploitation)
- **Compliance Boost:** +5 points if multiple frameworks affected

**Example:**
```powershell
$score = Calculate-RiskScore -Finding $finding

# Interpret score
switch ($score) {
    {$_ -ge 90} { "Critical" }
    {$_ -ge 70} { "High" }
    {$_ -ge 40} { "Medium" }
    default { "Low" }
}
```

---

### Get-RiskLevel

Gets the risk level classification for a risk score.

**Module:** EntraChecks-RiskScoring.psm1

**Syntax:**
```powershell
Get-RiskLevel
    -RiskScore <Int>
    [<CommonParameters>]
```

**Parameters:**
- `-RiskScore` (Int, Mandatory)
  - Risk score (0-100)

**Returns:**
- `[String]` - Risk level
  - `"Critical"` (90-100)
  - `"High"` (70-89)
  - `"Medium"` (40-69)
  - `"Low"` (0-39)

**Example:**
```powershell
Get-RiskLevel -RiskScore 95  # Returns "Critical"
Get-RiskLevel -RiskScore 75  # Returns "High"
Get-RiskLevel -RiskScore 50  # Returns "Medium"
Get-RiskLevel -RiskScore 20  # Returns "Low"
```

---

### Add-RiskScoring

Adds risk scoring and prioritization to finding objects.

**Module:** EntraChecks-RiskScoring.psm1

**Syntax:**
```powershell
Add-RiskScoring
    -Finding <Object>
    [<CommonParameters>]
```

**Parameters:**
- `-Finding` (Object, Mandatory, ValueFromPipeline)
  - Finding object to enhance

**Returns:**
- `[PSCustomObject]` - Finding with added properties:
  - `RiskScore` (Int) - Calculated risk score (0-100)
  - `RiskLevel` (String) - Risk classification
  - `RemediationEffort` (Int) - Effort level (1-5)
  - `RemediationEffortDescription` (String) - Effort description
  - `PriorityScore` (Double) - Priority score (Risk/Effort ratio)

**Example:**
```powershell
# Single finding
$enhancedFinding = $finding | Add-RiskScoring

# Multiple findings
$enhancedFindings = $findings | Add-RiskScoring

# Access new properties
$enhancedFinding.RiskScore         # e.g., 87
$enhancedFinding.RiskLevel         # e.g., "High"
$enhancedFinding.RemediationEffort # e.g., 2
$enhancedFinding.PriorityScore     # e.g., 43.5
```

---

### Get-RiskSummary

Generates statistical summary of risk across findings.

**Module:** EntraChecks-RiskScoring.psm1

**Syntax:**
```powershell
Get-RiskSummary
    -Findings <Array>
    [<CommonParameters>]
```

**Parameters:**
- `-Findings` (Array, Mandatory)
  - Array of findings (must be enhanced with risk scoring)

**Returns:**
- `[PSCustomObject]` with properties:
  - `TotalFindings` - Total count
  - `CriticalCount` / `HighCount` / `MediumCount` / `LowCount`
  - `CriticalPercent` / `HighPercent` / `MediumPercent` / `LowPercent`
  - `AverageRiskScore` - Mean risk score
  - `MaxRiskScore` / `MinRiskScore`
  - `QuickWinsCount` - High impact, low effort fixes
  - `ComplexCount` - High effort items
  - `TopPriorityCount` - Items with priority score >= 20

**Example:**
```powershell
$summary = Get-RiskSummary -Findings $enhancedFindings

# Display metrics
Write-Host "Critical: $($summary.CriticalCount) ($($summary.CriticalPercent)%)"
Write-Host "High: $($summary.HighCount) ($($summary.HighPercent)%)"
Write-Host "Average Risk: $($summary.AverageRiskScore)"
Write-Host "Quick Wins: $($summary.QuickWinsCount)"
```

---

### Get-PrioritizedFindings

Returns findings sorted by priority score (risk/effort ratio).

**Module:** EntraChecks-RiskScoring.psm1

**Syntax:**
```powershell
Get-PrioritizedFindings
    -Findings <Array>
    [-TopN <Int>]
    [<CommonParameters>]
```

**Parameters:**
- `-Findings` (Array, Mandatory)
  - Array of findings to prioritize

- `-TopN` (Int, Optional)
  - Number of top findings to return
  - Default: All findings

**Returns:**
- `[Array]` - Findings sorted by `PriorityScore` descending

**Example:**
```powershell
# Get all findings prioritized
$prioritized = Get-PrioritizedFindings -Findings $enhancedFindings

# Get top 10 priorities
$top10 = Get-PrioritizedFindings -Findings $enhancedFindings -TopN 10

# Display
$top10 | Select-Object Description, RiskLevel, PriorityScore | Format-Table
```

---

### Get-QuickWins

Identifies high-impact, low-effort fixes.

**Module:** EntraChecks-RiskScoring.psm1

**Syntax:**
```powershell
Get-QuickWins
    -Findings <Array>
    [<CommonParameters>]
```

**Parameters:**
- `-Findings` (Array, Mandatory)
  - Array of findings to analyze

**Returns:**
- `[Array]` - Findings meeting quick win criteria:
  - Risk score >= 50 (Medium to Critical)
  - Remediation effort <= 2 (Very Low to Low)
  - Sorted by priority score descending

**Example:**
```powershell
$quickWins = Get-QuickWins -Findings $enhancedFindings

Write-Host "Quick Wins: $($quickWins.Count) findings"

# Show quick wins
$quickWins | ForEach-Object {
    Write-Host "[$($_.RiskLevel)] $($_.Description)" -ForegroundColor Green
    Write-Host "  Effort: $($_.RemediationEffortDescription)"
    Write-Host "  Priority: $($_.PriorityScore)"
}
```

---

### Format-PriorityRecommendation

Formats priority recommendations for display.

**Module:** EntraChecks-RiskScoring.psm1

**Syntax:**
```powershell
Format-PriorityRecommendation
    -Findings <Array>
    [-Format <String>]
    [-TopN <Int>]
    [<CommonParameters>]
```

**Parameters:**
- `-Findings` (Array, Mandatory)
  - Prioritized findings array

- `-Format` (String, Optional)
  - Output format
  - Valid values: `"Text"`, `"HTML"`, `"Markdown"`
  - Default: `"Text"`

- `-TopN` (Int, Optional)
  - Number of top findings to include
  - Default: 25

**Returns:**
- `[String]` - Formatted priority recommendations

**Example:**
```powershell
$prioritized = Get-PrioritizedFindings -Findings $enhancedFindings

# Text format
$textReport = Format-PriorityRecommendation -Findings $prioritized -Format "Text" -TopN 10

# HTML format
$htmlReport = Format-PriorityRecommendation -Findings $prioritized -Format "HTML"

# Markdown format
$mdReport = Format-PriorityRecommendation -Findings $prioritized -Format "Markdown"
```

---

## Remediation Guidance Functions

### Get-RemediationGuidance

Gets detailed remediation guidance for a finding type.

**Module:** EntraChecks-RemediationGuidance.psm1

**Syntax:**
```powershell
Get-RemediationGuidance
    -FindingType <String>
    [<CommonParameters>]
```

**Parameters:**
- `-FindingType` (String, Mandatory)
  - Type of finding to get guidance for

**Returns:**
- `[Hashtable]` with guidance properties:
  - `Title` - Descriptive title
  - `Summary` - Brief overview
  - `Impact` - Hashtable with `Positive` and `Negative` strings
  - `Prerequisites` - Array of prerequisites
  - `StepsPortal` - Array of Azure Portal steps
  - `StepsPowerShell` - PowerShell automation script
  - `Verification` - Array of verification steps
  - `Rollback` - Array of rollback procedures
  - `CommonIssues` - Array of troubleshooting tips
  - `References` - Array of documentation URLs

**Example:**
```powershell
$guidance = Get-RemediationGuidance -FindingType "MFA_Disabled"

# Display title and summary
Write-Host $guidance.Title
Write-Host $guidance.Summary

# Show Azure Portal steps
$guidance.StepsPortal | ForEach-Object { Write-Host $_ }

# Get PowerShell commands
Write-Host $guidance.StepsPowerShell

# Check prerequisites
$guidance.Prerequisites | ForEach-Object { Write-Host "- $_" }
```

---

### Add-RemediationGuidance

Adds remediation guidance to finding objects.

**Module:** EntraChecks-RemediationGuidance.psm1

**Syntax:**
```powershell
Add-RemediationGuidance
    -Finding <Object>
    [<CommonParameters>]
```

**Parameters:**
- `-Finding` (Object, Mandatory, ValueFromPipeline)
  - Finding object to enhance

**Returns:**
- `[PSCustomObject]` - Finding with added `RemediationGuidance` property (hashtable)

**Example:**
```powershell
# Single finding
$enhancedFinding = $finding | Add-RemediationGuidance

# Multiple findings
$enhancedFindings = $findings | Add-RemediationGuidance

# Access guidance
$enhancedFinding.RemediationGuidance.Title
$enhancedFinding.RemediationGuidance.StepsPortal
$enhancedFinding.RemediationGuidance.StepsPowerShell
```

---

### Format-RemediationSteps

Formats remediation steps for different output types.

**Module:** EntraChecks-RemediationGuidance.psm1

**Syntax:**
```powershell
Format-RemediationSteps
    -Guidance <Hashtable>
    [-Format <String>]
    [-IncludeSections <String>]
    [<CommonParameters>]
```

**Parameters:**
- `-Guidance` (Hashtable, Mandatory)
  - Remediation guidance hashtable

- `-Format` (String, Optional)
  - Output format
  - Valid values: `"Text"`, `"HTML"`, `"Markdown"`
  - Default: `"Text"`

- `-IncludeSections` (String, Optional)
  - Which sections to include
  - Valid values: `"All"`, `"SummaryOnly"`, `"StepsOnly"`
  - Default: `"All"`

**Returns:**
- `[String]` - Formatted remediation steps

**Example:**
```powershell
$guidance = Get-RemediationGuidance -FindingType "MFA_Disabled"

# Full guidance in text format
$textGuide = Format-RemediationSteps -Guidance $guidance -Format "Text"

# Only steps in HTML format
$htmlSteps = Format-RemediationSteps -Guidance $guidance -Format "HTML" -IncludeSections "StepsOnly"

# Summary only in Markdown
$mdSummary = Format-RemediationSteps -Guidance $guidance -Format "Markdown" -IncludeSections "SummaryOnly"

# Display or save
$textGuide | Out-File "remediation.txt"
```

---

## HTML Reporting Functions

### New-EnhancedHTMLReport

Generates a complete interactive HTML report.

**Module:** EntraChecks-HTMLReporting.psm1

**Syntax:**
```powershell
New-EnhancedHTMLReport
    -Findings <Array>
    -OutputPath <String>
    -TenantInfo <Object>
    [<CommonParameters>]
```

**Parameters:**
- `-Findings` (Array, Mandatory)
  - Array of enhanced findings
  - Must be enhanced with risk scoring, compliance mapping, and remediation guidance

- `-OutputPath` (String, Mandatory)
  - Path to save the HTML file
  - Example: `".\Report.html"`, `"C:\Reports\EntraChecks-2026-02-10.html"`

- `-TenantInfo` (Object, Mandatory)
  - PSCustomObject with properties:
    - `TenantName` (String) - Display name
    - `TenantId` (String) - Tenant ID (GUID)

**Returns:**
- `[String]` - Path to generated HTML file

**Report Sections:**
1. Header with tenant information
2. Executive dashboard with KPIs
3. Quick wins section (top 5)
4. Priority findings (top 25)
5. Compliance framework mapping
6. Detailed findings (all, grouped by risk level)

**Interactive Features:**
- Collapsible finding cards (click to expand/collapse)
- Real-time search across all findings
- Risk level filtering (Critical/High/Medium/Low)
- Smooth navigation menu
- Responsive design (mobile-friendly)

**Example:**
```powershell
# Basic usage
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

New-EnhancedHTMLReport `
    -Findings $enhancedFindings `
    -OutputPath ".\EntraChecks-Report.html" `
    -TenantInfo $tenantInfo

# With timestamp in filename
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$htmlPath = ".\EntraChecks-$timestamp.html"

New-EnhancedHTMLReport `
    -Findings $enhancedFindings `
    -OutputPath $htmlPath `
    -TenantInfo $tenantInfo

# Open in browser
Start-Process $htmlPath
```

**Output Example:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Entra ID Security Assessment - Contoso Ltd</title>
    <style>
        /* Professional styling with colors for risk levels */
    </style>
</head>
<body>
    <!-- Navigation bar -->
    <!-- Executive dashboard with metrics -->
    <!-- Quick wins section -->
    <!-- Priority findings table -->
    <!-- Compliance framework cards -->
    <!-- Detailed findings (collapsible cards) -->
    <!-- JavaScript for interactivity -->
</body>
</html>
```

---

## Excel Reporting Functions

### New-EnhancedExcelReport

Generates a multi-sheet Excel workbook.

**Module:** EntraChecks-ExcelReporting.psm1

**Syntax:**
```powershell
New-EnhancedExcelReport
    -Findings <Array>
    -OutputPath <String>
    -TenantInfo <Object>
    [-UseImportExcel]
    [<CommonParameters>]
```

**Parameters:**
- `-Findings` (Array, Mandatory)
  - Array of enhanced findings

- `-OutputPath` (String, Mandatory)
  - Path to save the Excel file
  - Example: `".\Report.xlsx"`, `"C:\Reports\EntraChecks-2026-02-10.xlsx"`

- `-TenantInfo` (Object, Mandatory)
  - PSCustomObject with `TenantName` and `TenantId` properties

- `-UseImportExcel` (Switch, Optional)
  - Use ImportExcel module to create .xlsx file
  - If not specified or module not available, creates CSV files instead

**Returns:**
- `[String]` - Path to generated Excel file or folder

**Excel Sheets:**
1. **Executive Summary** - Key metrics and KPIs
2. **All Findings** - Complete list with all columns (sortable/filterable)
3. **Priority Findings** - Top 25 by priority score
4. **Quick Wins** - High ROI fixes
5. **Compliance - CIS M365** - CIS-mapped findings
6. **Compliance - NIST CSF** - NIST-mapped findings
7. **Compliance - SOC2** - SOC2-mapped findings
8. **Compliance - PCI-DSS** - PCI-DSS-mapped findings
9. **Risk Analysis** - Statistical breakdown

**Sheet Features:**
- Bold top row headers
- Frozen header rows
- Auto-sized columns
- Auto-filters on data sheets
- Properly formatted dates and numbers

**Example:**
```powershell
# With ImportExcel module
New-EnhancedExcelReport `
    -Findings $enhancedFindings `
    -OutputPath ".\EntraChecks-Report.xlsx" `
    -TenantInfo $tenantInfo `
    -UseImportExcel

# Without ImportExcel (creates CSV files)
New-EnhancedExcelReport `
    -Findings $enhancedFindings `
    -OutputPath ".\EntraChecks-Report.xlsx" `
    -TenantInfo $tenantInfo
# Creates folder: EntraChecks-Report with multiple CSV files

# Open in Excel
Start-Process ".\EntraChecks-Report.xlsx"

# Open in Excel Online (if using CSV)
Start-Process "https://www.office.com/launch/excel"
```

**CSV Fallback:**
When ImportExcel is not available, creates a folder with CSV files:
- `ExecutiveSummary.csv`
- `AllFindings.csv`
- `PriorityFindings.csv`
- `QuickWins.csv`
- `Compliance-CIS.csv`
- `Compliance-NIST.csv`
- `Compliance-SOC2.csv`
- `Compliance-PCIDSS.csv`
- `RiskAnalysis.csv`

---

## Common Patterns

### Full Enhancement Pipeline

```powershell
# Connect and scan
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "Organization.Read.All"
.\EntraChecks.ps1

# Import modules
Import-Module .\Modules\*.psm1 -Force

# Get tenant info
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

# Full enhancement pipeline
$enhancedFindings = $findings |
    Add-RiskScoring |
    Add-ComplianceMapping |
    Add-RemediationGuidance

# Generate reports
New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath ".\Report.html" -TenantInfo $tenantInfo
New-EnhancedExcelReport -Findings $enhancedFindings -OutputPath ".\Report.xlsx" -TenantInfo $tenantInfo -UseImportExcel

# Cleanup
Disconnect-MgGraph
```

### Error Handling Pattern

```powershell
try {
    # Import modules
    Import-Module .\Modules\*.psm1 -Force -ErrorAction Stop

    # Enhance findings with error handling at each step
    $enhancedFindings = @()
    foreach ($finding in $findings) {
        try {
            $enhanced = $finding |
                Add-RiskScoring |
                Add-ComplianceMapping |
                Add-RemediationGuidance
            $enhancedFindings += $enhanced
        }
        catch {
            Write-Warning "Failed to enhance finding: $($finding.Description)"
            Write-Warning $_.Exception.Message
            # Add original finding without enhancements
            $enhancedFindings += $finding
        }
    }

    # Generate report
    New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath ".\Report.html" -TenantInfo $tenantInfo

} catch {
    Write-Error "Report generation failed: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
} finally {
    Disconnect-MgGraph
}
```

---

## Version History

### Version 1.0.0 (2026-02-10)
- Initial release
- 5 modules with 23 exported functions
- Support for 4 compliance frameworks
- HTML and Excel report generation
- Interactive dashboards and filtering

---

**Related Documentation:**
- [GETTING-STARTED.md](GETTING-STARTED.md) - Beginner's tutorial
- [USER-GUIDE.md](USER-GUIDE.md) - Comprehensive user guide
- [EXAMPLES.md](EXAMPLES.md) - Practical usage examples
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions

# Getting Started with EntraChecks Reporting - Complete Beginner's Guide

**Welcome!** This guide will teach you everything you need to know to use the EntraChecks reporting modules, even if you've never used PowerShell before.

---

## Table of Contents

1. [What is EntraChecks?](#what-is-entrachecks)
2. [What You'll Need](#what-youll-need)
3. [Understanding the Basics](#understanding-the-basics)
4. [Step-by-Step Tutorial](#step-by-step-tutorial)
5. [Your First Report](#your-first-report)
6. [Understanding the Output](#understanding-the-output)
7. [Next Steps](#next-steps)

---

## What is EntraChecks?

EntraChecks is a security assessment tool for **Microsoft Entra ID** (formerly Azure Active Directory). It checks your organization's cloud identity settings and finds potential security issues.

### What do the reporting modules do?

The reporting modules take the security findings from EntraChecks and create beautiful, professional reports that include:

- **Risk Scores** - How dangerous each issue is (Critical, High, Medium, Low)
- **Priority Rankings** - Which issues to fix first for maximum security improvement
- **Compliance Mappings** - How findings relate to standards like CIS, NIST, SOC2, PCI-DSS
- **Remediation Steps** - Detailed instructions on how to fix each issue
- **HTML Reports** - Interactive web-based reports with dashboards
- **Excel Reports** - Multi-sheet workbooks with charts and analysis

---

## What You'll Need

### Required Software

1. **Windows PowerShell** (already installed on Windows)
   - Windows 10/11: Already included
   - To check: Press `Win + X`, select "Windows PowerShell"

2. **Microsoft Graph PowerShell Module** (for connecting to Entra ID)
   - We'll install this together in the tutorial

3. **ImportExcel Module** (optional, for Excel reports)
   - We'll install this together if you want Excel reports

### Required Permissions

To scan your Entra ID tenant, you need:
- **Global Administrator** OR
- **Global Reader** OR
- **Security Reader**

If you don't have these permissions, ask your IT administrator.

---

## Understanding the Basics

### What is PowerShell?

PowerShell is a command-line tool built into Windows. Think of it as a way to give your computer instructions by typing commands instead of clicking buttons.

**Don't worry!** We'll guide you through every command.

### Opening PowerShell

1. Press `Win + X` on your keyboard
2. Select "Windows PowerShell" (or "Windows PowerShell (Admin)" for administrator mode)
3. A blue/black window will open - this is PowerShell!

### Basic PowerShell Commands You'll Use

```powershell
# Lines starting with # are comments - they don't do anything
# They're just notes to help you understand

# Get-Help: Shows help for a command
Get-Help Import-Module

# Get-Location: Shows your current folder
Get-Location

# Set-Location: Changes to a different folder
Set-Location "C:\MyFolder"

# Get-ChildItem: Lists files in current folder (like 'dir')
Get-ChildItem
```

**Pro Tip:** You can use `↑` and `↓` arrow keys to scroll through previous commands!

---

## Step-by-Step Tutorial

### Step 1: Navigate to the EntraChecks Folder

First, we need to tell PowerShell where to find the EntraChecks files.

```powershell
# Change this path to where YOU downloaded EntraChecks
Set-Location "C:\Users\stell\Downloads\EntraChecks-v1.0.0_1\EntraChecks"
```

**How to find your path:**
1. Open File Explorer
2. Navigate to the EntraChecks folder
3. Click in the address bar at the top
4. Copy the path (Ctrl + C)
5. Paste it between the quotes above

**Verify you're in the right place:**
```powershell
Get-ChildItem
```

You should see files like:
- `EntraChecks.ps1`
- A folder called `Modules`
- Other configuration files

---

### Step 2: Install Required PowerShell Modules

We need to install some helper modules that EntraChecks uses.

#### Install Microsoft Graph PowerShell

```powershell
# This command installs the Microsoft Graph module
# You'll be asked "Do you trust this repository?" - Type Y and press Enter
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

**What this does:** Downloads the tools needed to connect to Microsoft Entra ID.

**Time required:** 2-5 minutes (depending on internet speed)

#### Install ImportExcel Module (Optional - for Excel reports)

```powershell
# This allows you to create Excel files without having Microsoft Excel installed
Install-Module ImportExcel -Scope CurrentUser -Force
```

**What this does:** Allows creation of Excel files with multiple sheets.

**Time required:** 30 seconds - 1 minute

---

### Step 3: Import the EntraChecks Reporting Modules

Now we'll load the reporting modules into PowerShell.

```powershell
# Import all five reporting modules
Import-Module .\Modules\EntraChecks-ComplianceMapping.psm1 -Force
Import-Module .\Modules\EntraChecks-RiskScoring.psm1 -Force
Import-Module .\Modules\EntraChecks-RemediationGuidance.psm1 -Force
Import-Module .\Modules\EntraChecks-HTMLReporting.psm1 -Force
Import-Module .\Modules\EntraChecks-ExcelReporting.psm1 -Force

Write-Host "All modules loaded successfully!" -ForegroundColor Green
```

**What this does:** Makes all the reporting functions available for you to use.

**Expected output:** You might see some warnings about "unapproved verbs" - this is normal and safe to ignore.

---

### Step 4: Connect to Your Entra ID Tenant

Before we can scan for issues, we need to connect to your organization's Entra ID.

```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "Organization.Read.All"
```

**What will happen:**
1. A web browser window will open
2. Sign in with your work/school account
3. You'll be asked to approve permissions
4. Click "Accept"
5. You can close the browser window
6. PowerShell will say "Welcome To Microsoft Graph!"

**Troubleshooting:**
- If you get "insufficient permissions" - you need Global Reader or Security Reader role
- If browser doesn't open - check your firewall settings

---

### Step 5: Run the EntraChecks Scan

Now we'll scan your Entra ID tenant for security issues.

```powershell
# Run the main EntraChecks script
.\EntraChecks.ps1
```

**What will happen:**
1. The script will check dozens of security settings
2. You'll see progress messages like "Checking MFA policies..."
3. This takes 2-5 minutes depending on your tenant size
4. Results are saved to a variable called `$findings`

**Expected output:**
```
Starting EntraChecks Security Assessment...
Checking tenant information...
Checking MFA policies...
Checking Conditional Access policies...
...
Scan complete! Found 47 findings.
```

**Note:** The number of findings will vary based on your tenant's configuration.

---

## Your First Report

Now that we have scan results, let's create your first report!

### Creating an HTML Report

This creates an interactive web page with all your findings.

```powershell
# Prepare the output file path
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$htmlPath = ".\EntraChecks-Report-$timestamp.html"

# Get tenant information
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

# Enhance findings with risk scoring and compliance mapping
Write-Host "Enhancing findings with metadata..." -ForegroundColor Cyan
$enhancedFindings = @()
foreach ($finding in $findings) {
    $enhanced = $finding |
        Add-RiskScoring |
        Add-ComplianceMapping |
        Add-RemediationGuidance
    $enhancedFindings += $enhanced
}

# Generate the HTML report
Write-Host "Generating HTML report..." -ForegroundColor Cyan
New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath $htmlPath -TenantInfo $tenantInfo

Write-Host "`nReport created successfully!" -ForegroundColor Green
Write-Host "Location: $htmlPath" -ForegroundColor Yellow
Write-Host "`nOpening report in your default browser..." -ForegroundColor Cyan
Start-Process $htmlPath
```

**What this does:**
1. **Lines 2-3:** Creates a filename with today's date/time
2. **Lines 6-9:** Gets your tenant name and ID
3. **Lines 12-19:** Adds risk scores, compliance mappings, and remediation guidance to each finding
4. **Lines 22-23:** Creates the HTML report file
5. **Lines 28:** Opens the report in your web browser

**Time required:** 30 seconds - 2 minutes

**What you'll see:**
- The report will open in your default web browser
- An interactive dashboard showing risk summary
- Quick wins (high-impact, low-effort fixes)
- Prioritized findings
- Detailed remediation steps

---

### Creating an Excel Report

This creates a multi-sheet Excel workbook with charts and analysis.

```powershell
# Make sure you have ImportExcel module installed
# If you skipped Step 2, run this now:
# Install-Module ImportExcel -Scope CurrentUser -Force

# Prepare the output file path
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
$excelPath = ".\EntraChecks-Report-$timestamp.xlsx"

# Generate the Excel report
Write-Host "Generating Excel report..." -ForegroundColor Cyan
New-EnhancedExcelReport -Findings $enhancedFindings -OutputPath $excelPath -TenantInfo $tenantInfo -UseImportExcel

Write-Host "`nExcel report created successfully!" -ForegroundColor Green
Write-Host "Location: $excelPath" -ForegroundColor Yellow
Write-Host "`nOpening Excel report..." -ForegroundColor Cyan
Start-Process $excelPath
```

**What this does:**
- Creates an Excel file with multiple sheets:
  - **Executive Summary** - High-level metrics and KPIs
  - **All Findings** - Complete list with risk scores
  - **Priority Findings** - Top 25 issues to fix first
  - **Quick Wins** - Easy wins for quick security improvements
  - **Compliance Sheets** - Findings mapped to CIS, NIST, SOC2, PCI-DSS
  - **Risk Analysis** - Statistical breakdown

**Time required:** 1-3 minutes

---

## Understanding the Output

### HTML Report Sections

When you open the HTML report, you'll see these sections:

#### 1. **Executive Summary** 📊
- Total findings count
- Risk distribution (Critical, High, Medium, Low)
- Average risk score
- Quick wins available
- Compliance framework impact

**What to look for:**
- High number of Critical or High risk findings = urgent action needed
- Quick wins count = easy improvements you can make today

#### 2. **Quick Wins** ⚡
- High-impact fixes that are easy to implement
- Sorted by priority score (risk divided by effort)

**Action:** Start here! These give you the most security improvement with least effort.

#### 3. **Top Priority Findings** 🎯
- Top 25 findings ranked by priority
- Considers both risk and remediation effort

**Action:** This is your roadmap - fix these in order for best results.

#### 4. **Compliance Framework Mapping** 📋
- Shows which compliance controls are affected
- Helps with audit preparation

**Action:** If you're working toward certification (SOC2, PCI-DSS, etc.), focus on these.

#### 5. **Detailed Findings** 🔍
- Every finding with full details
- Grouped by risk level (Critical → Low)
- Click to expand for remediation steps

**What you'll see for each finding:**
- **Description** - What the issue is
- **Risk Score** - Numerical risk (0-100)
- **Risk Level** - Critical, High, Medium, or Low
- **Object** - What's affected (user, policy, etc.)
- **Remediation Steps** - How to fix it (Azure Portal steps)
- **PowerShell Commands** - Automated fix commands
- **Impact Analysis** - Positive and negative effects of fixing

---

### Excel Report Sheets

#### **Executive Summary Sheet**
- Key metrics in table format
- Easy to copy into presentations
- Risk and compliance summary

#### **All Findings Sheet**
- Sortable and filterable
- All findings with risk scores
- Use filters to focus on specific risk levels

#### **Priority Findings Sheet**
- Ranked 1-25
- Your action plan
- Shows risk, effort, and priority score

#### **Quick Wins Sheet**
- High ROI fixes
- Sorted by priority score
- Focus here first for quick wins

#### **Compliance Sheets** (CIS M365, NIST CSF, SOC2, PCI-DSS)
- Findings mapped to specific controls
- Useful for audit preparation
- Shows which controls have gaps

#### **Risk Analysis Sheet**
- Statistical breakdown
- Risk distribution metrics
- Remediation effort analysis

---

## Next Steps

### Recommended Workflow

1. **Review Executive Summary**
   - Understand your overall security posture
   - Note the risk distribution

2. **Start with Quick Wins**
   - Implement the easiest, highest-impact fixes
   - These often take less than 30 minutes each

3. **Work Through Priorities**
   - Fix top priority findings in order
   - Track progress in the Excel sheet

4. **Re-scan Regularly**
   - Run EntraChecks monthly
   - Track improvement over time
   - Catch new issues early

### Sharing Reports with Your Team

**HTML Reports:**
- Can be opened in any web browser
- Send via email or SharePoint
- No special software needed

**Excel Reports:**
- Can be opened in Excel or Excel Online
- Easy to share and collaborate
- Add notes and track remediation progress

### Advanced Usage

Once you're comfortable with the basics, check out:
- [USER-GUIDE.md](USER-GUIDE.md) - Complete reference documentation
- [EXAMPLES.md](EXAMPLES.md) - Advanced usage examples
- [API-REFERENCE.md](API-REFERENCE.md) - Function reference guide
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Common issues and solutions

---

## Common Beginner Questions

### "How often should I run EntraChecks?"

**Recommended:** Monthly, or after major changes to your Entra ID configuration.

### "Can I automate the scanning and reporting?"

**Yes!** See the USER-GUIDE.md for automation examples using scheduled tasks.

### "Do I need Microsoft Excel to view Excel reports?"

**No!** The reports work with:
- Microsoft Excel (desktop or online)
- Google Sheets (upload the file)
- LibreOffice Calc (free alternative)

### "What if I get 'insufficient permissions' errors?"

You need one of these roles assigned to your account:
- Global Administrator
- Global Reader
- Security Reader

Ask your IT administrator to grant the appropriate role.

### "Can I scan multiple tenants?"

**Yes!** Disconnect from the current tenant and connect to the next one:
```powershell
Disconnect-MgGraph
Connect-MgGraph -Scopes "Directory.Read.All", "Policy.Read.All", "Organization.Read.All"
# Then run .\EntraChecks.ps1 again
```

### "Are the PowerShell remediation commands safe to run?"

The commands are safe but always:
1. **Read and understand** what the command does first
2. **Test in a non-production environment** if possible
3. **Have a rollback plan** (the reports include rollback steps)
4. **Take a backup** (export current settings before making changes)

### "What does 'Risk Score' mean?"

Risk scores range from 0-100:
- **90-100:** Critical - Fix immediately
- **70-89:** High - Fix within 1 week
- **40-69:** Medium - Fix within 1 month
- **0-39:** Low - Fix when convenient

Scores are calculated based on:
- Severity of the vulnerability
- Scope of impact (how many users affected)
- Exploitability (how easy to attack)
- Compliance requirements

---

## Getting Help

### If You Get Stuck

1. **Check the error message** - PowerShell errors usually explain what went wrong
2. **Review TROUBLESHOOTING.md** - Common issues and solutions
3. **Check permissions** - Most issues are permission-related
4. **Search online** - Copy/paste the error into Google

### Useful PowerShell Commands for Troubleshooting

```powershell
# See what modules are loaded
Get-Module

# See what commands are available from a module
Get-Command -Module EntraChecks-RiskScoring

# Get detailed help for a function
Get-Help New-EnhancedHTMLReport -Detailed

# Check your current connection to Microsoft Graph
Get-MgContext

# See what permissions you have
(Get-MgContext).Scopes
```

---

## Congratulations! 🎉

You've completed the beginner's tutorial! You now know how to:

✅ Install required PowerShell modules
✅ Connect to Microsoft Entra ID
✅ Run security assessments with EntraChecks
✅ Generate professional HTML and Excel reports
✅ Understand risk scores and priorities
✅ Find and fix security issues

**Remember:** Security is an ongoing process. Run EntraChecks regularly to stay on top of your Entra ID security posture!

---

## Quick Reference Card

### Essential Commands (Copy & Paste)

```powershell
# Navigate to EntraChecks folder
Set-Location "C:\Path\To\EntraChecks"

# Import all modules
Import-Module .\Modules\*.psm1 -Force

# Connect to Entra ID
Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","Organization.Read.All"

# Run scan
.\EntraChecks.ps1

# Get tenant info
$tenantInfo = [PSCustomObject]@{
    TenantName = (Get-MgOrganization).DisplayName
    TenantId = (Get-MgOrganization).Id
}

# Enhance findings
$enhancedFindings = $findings | Add-RiskScoring | Add-ComplianceMapping | Add-RemediationGuidance

# Create HTML report
New-EnhancedHTMLReport -Findings $enhancedFindings -OutputPath ".\Report.html" -TenantInfo $tenantInfo

# Create Excel report
New-EnhancedExcelReport -Findings $enhancedFindings -OutputPath ".\Report.xlsx" -TenantInfo $tenantInfo -UseImportExcel

# Disconnect when done
Disconnect-MgGraph
```

---

**Need more help?** Check out the other documentation files:
- 📘 [USER-GUIDE.md](USER-GUIDE.md) - Comprehensive documentation
- 💡 [EXAMPLES.md](EXAMPLES.md) - Real-world usage examples
- 🔧 [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Problem solving
- 📚 [API-REFERENCE.md](API-REFERENCE.md) - Function reference

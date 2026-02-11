# EntraChecks Code Quality Guide

## Overview

EntraChecks uses PSScriptAnalyzer for automated code quality analysis. This ensures consistent coding standards, identifies potential bugs, enforces best practices, and catches security issues before they reach production.

## Quick Start

### Run Code Quality Check

```powershell
# Basic analysis (errors and warnings)
.\Invoke-CodeQualityCheck.ps1

# Include informational messages
.\Invoke-CodeQualityCheck.ps1 -Severity Information

# Export detailed reports
.\Invoke-CodeQualityCheck.ps1 -ExportResults

# CI/CD mode (fail on errors)
.\Invoke-CodeQualityCheck.ps1 -FailOnErrors
```

### View Reports

Reports are generated in `.\CodeQualityReports\` when using `-ExportResults`:
- **JSON**: Machine-readable full results
- **CSV**: Spreadsheet-friendly format
- **HTML**: Visual report with summary and details

## Current Code Quality Status

**Last Analysis**: February 10, 2026

### Summary

- **Files Analyzed**: 22 PowerShell files
- **Files with Issues**: 20
- **Total Issues**: 1,936
  - **Errors**: 1 (Critical - Security)
  - **Warnings**: 1,935 (Mostly formatting)

### Issues Breakdown

| Rule | Count | Severity | Category | Priority |
|------|-------|----------|----------|----------|
| PSAlignAssignmentStatement | 1,642 | Warning | Formatting | Low |
| PSUseConsistentIndentation | 135 | Warning | Formatting | Low |
| PSUseConsistentWhitespace | 73 | Warning | Formatting | Low |
| PSUseSingularNouns | 58 | Warning | Naming | Medium |
| PSUseDeclaredVarsMoreThanAssignments | 13 | Warning | Code Quality | Medium |
| PSAvoidUsingEmptyCatchBlock | 10 | Warning | Error Handling | High |
| PSUseApprovedVerbs | 3 | Warning | Naming | Medium |
| PSAvoidUsingConvertToSecureStringWithPlainText | 1 | **Error** | **Security** | **Critical** |
| PSAvoidDefaultValueSwitchParameter | 1 | Warning | Best Practice | Low |

### Top Files Requiring Attention

1. **EntraChecks-Compliance.psm1** - 489 issues (mostly formatting)
2. **EntraChecks-Configuration.psm1** - 229 issues (mostly formatting)
3. **EntraChecks-DeltaReporting.psm1** - 188 issues (mostly formatting)
4. **Invoke-EntraChecks.ps1** - 144 issues (1 error, 143 warnings)

## Issue Categories & Remediation

### Critical Issues (Must Fix)

#### 1. PSAvoidUsingConvertToSecureStringWithPlainText

**Location**: [Invoke-EntraChecks.ps1](../Invoke-EntraChecks.ps1)

**Issue**: Using `ConvertTo-SecureString` with `-AsPlainText` parameter

**Risk**: Security vulnerability - plain text passwords in code

**Remediation**:
```powershell
# Bad - Plain text password
$securePassword = ConvertTo-SecureString "password123" -AsPlainText -Force

# Good - Read from secure source
$securePassword = Read-Host "Enter password" -AsSecureString

# Good - Use credential object
$cred = Get-Credential

# Good - Read from environment variable (for automation)
$securePassword = $env:PASSWORD | ConvertTo-SecureString -AsPlainText -Force
# Note: Only acceptable if password comes from secure secret management
```

**Action Required**: Update authentication code to use secure password input methods.

### High Priority Issues (Should Fix)

#### 2. PSAvoidUsingEmptyCatchBlock (10 occurrences)

**Issue**: Empty catch blocks hide errors

**Risk**: Silent failures make debugging difficult

**Remediation**:
```powershell
# Bad - Empty catch
try {
    Do-Something
}
catch {
    # Empty - error is silently ignored
}

# Good - Log error
try {
    Do-Something
}
catch {
    Write-Log -Level ERROR -Message "Operation failed" -ErrorRecord $_
    throw  # Re-throw if critical
}

# Good - Specific error handling
try {
    Do-Something
}
catch {
    Write-Log -Level WARN -Message "Operation failed, using default" -ErrorRecord $_
    $defaultValue  # Return default on error
}
```

**Action Required**: Review all catch blocks and add appropriate error handling.

### Medium Priority Issues (Should Address)

#### 3. PSUseSingularNouns (58 occurrences)

**Issue**: Function names use plural nouns (e.g., `Get-Users`)

**Standard**: PowerShell functions should use singular nouns

**Remediation**:
```powershell
# Bad
function Get-Users { }
function Test-Credentials { }

# Good
function Get-User { }
function Test-Credential { }
```

**Note**: Many of these may be intentional (returning multiple items). Consider using approved verbs like `Find-` or keeping current names if they accurately reflect functionality.

#### 4. PSUseApprovedVerbs (3 occurrences)

**Issue**: Non-standard verbs in function names

**Standard**: Use approved PowerShell verbs (Get, Set, New, Remove, etc.)

**Check Approved Verbs**:
```powershell
Get-Verb | Format-Table -AutoSize
```

**Common Violations**:
- `Start-` → Use `Initialize-` or `Invoke-`
- `Perform-` → Use `Invoke-`
- `Calculate-` → Use `Measure-`

**Action Required**: Review function names and use approved verbs where possible.

#### 5. PSUseDeclaredVarsMoreThanAssignments (13 occurrences)

**Issue**: Variables declared but not used

**Risk**: Code clutter, potential bugs

**Remediation**:
```powershell
# Bad - Variable assigned but not used
$unusedVariable = Get-Something
Do-SomethingElse

# Good - Remove unused variables
Do-SomethingElse

# Good - Use the variable
$result = Get-Something
Write-Output $result
```

**Action Required**: Review and remove unused variables or suppress if intentional.

### Low Priority Issues (Nice to Fix)

#### 6. Formatting Issues (1,850 occurrences)

**Rules**:
- `PSAlignAssignmentStatement` (1,642)
- `PSUseConsistentIndentation` (135)
- `PSUseConsistentWhitespace` (73)

**Issue**: Inconsistent formatting and alignment

**Impact**: Code readability

**Remediation**: Use automated formatter

**Auto-Fix with Invoke-Formatter**:
```powershell
# Format a single file
$formatted = Invoke-Formatter -ScriptDefinition (Get-Content .\MyScript.ps1 -Raw) -Settings .\PSScriptAnalyzerSettings.psd1
$formatted | Set-Content .\MyScript.ps1

# Format all files
Get-ChildItem -Path . -Include *.ps1,*.psm1 -Recurse | ForEach-Object {
    $formatted = Invoke-Formatter -ScriptDefinition (Get-Content $_.FullName -Raw) -Settings .\PSScriptAnalyzerSettings.psd1
    $formatted | Set-Content $_.FullName -Encoding UTF8
}
```

**Note**: Test thoroughly after auto-formatting as it may change code behavior in edge cases.

## PSScriptAnalyzer Configuration

### Settings File: PSScriptAnalyzerSettings.psd1

Our configuration includes:

**Severity Levels**: Error, Warning (Information excluded by default)

**Excluded Rules**:
- `PSAvoidUsingWriteHost` - We use Write-Host for user output intentionally
- `PSAvoidUsingCmdletAliases` - We use aliases in display functions for brevity
- `PSUseShouldProcessForStateChangingFunctions` - Not applicable for read-only assessment tool

**Key Rules Enabled**:
- Security: Password handling, injection prevention
- Best Practices: Approved verbs, singular nouns, error handling
- Code Style: Consistent indentation, whitespace, alignment
- Performance: Empty catch blocks, credential types

### Customizing Rules

Edit `PSScriptAnalyzerSettings.psd1`:

```powershell
@{
    # Add rule to exclude
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'YourRuleHere'
    )

    # Configure rule settings
    Rules = @{
        PSUseConsistentIndentation = @{
            Enable = $true
            IndentationSize = 4
            Kind = 'space'
        }
    }
}
```

## Usage Patterns

### Local Development

```powershell
# Quick check before commit
.\Invoke-CodeQualityCheck.ps1

# Detailed analysis with reports
.\Invoke-CodeQualityCheck.ps1 -ExportResults

# Check specific file
.\Invoke-CodeQualityCheck.ps1 -Path .\Modules\EntraChecks-Logging.psm1 -Recurse:$false
```

### Pre-Commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/sh
# Run PSScriptAnalyzer before commit

echo "Running code quality checks..."
powershell.exe -ExecutionPolicy Bypass -File "./Invoke-CodeQualityCheck.ps1" -FailOnErrors

if [ $? -ne 0 ]; then
    echo "Code quality check failed. Commit aborted."
    echo "Fix errors or use 'git commit --no-verify' to bypass."
    exit 1
fi

echo "Code quality check passed."
exit 0
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: Code Quality

on: [push, pull_request]

jobs:
  analyze:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run PSScriptAnalyzer
        shell: pwsh
        run: |
          .\Invoke-CodeQualityCheck.ps1 -FailOnErrors -ExportResults

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: code-quality-report
          path: CodeQualityReports/
```

#### Azure DevOps

```yaml
trigger:
  - main

pool:
  vmImage: 'windows-latest'

steps:
- task: PowerShell@2
  displayName: 'Run Code Quality Check'
  inputs:
    targetType: 'filePath'
    filePath: '$(Build.SourcesDirectory)\Invoke-CodeQualityCheck.ps1'
    arguments: '-FailOnErrors -ExportResults'
    errorActionPreference: 'stop'

- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    PathtoPublish: '$(Build.SourcesDirectory)\CodeQualityReports'
    ArtifactName: 'CodeQualityReports'
```

## Best Practices

### 1. Run Locally Before Commit

Always run code quality checks before committing:

```powershell
.\Invoke-CodeQualityCheck.ps1 -FailOnErrors
```

### 2. Fix Critical Issues First

Priority order:
1. **Errors** (Security, Critical Bugs)
2. **High-Priority Warnings** (Empty catch blocks, unused variables)
3. **Medium-Priority Warnings** (Naming conventions)
4. **Low-Priority Warnings** (Formatting)

### 3. Use Suppression Sparingly

Suppress rules only when justified:

```powershell
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification='Function returns multiple items')]
function Get-Users {
    # Function that genuinely returns multiple users
}
```

### 4. Document Suppressions

Always add justification:

```powershell
# Suppress for valid reason
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='User-facing output, not logging')]
function Show-Report {
    Write-Host "Report:" -ForegroundColor Cyan
}
```

### 5. Automate Formatting

Use `Invoke-Formatter` for consistent code style:

```powershell
# Format before commit
Invoke-Formatter -ScriptDefinition (Get-Content .\MyScript.ps1 -Raw) -Settings .\PSScriptAnalyzerSettings.psd1 | Set-Content .\MyScript.ps1
```

### 6. Review Reports Regularly

Export and review reports periodically:

```powershell
.\Invoke-CodeQualityCheck.ps1 -ExportResults
# Open CodeQualityReports\CodeQuality_*.html
```

### 7. Track Progress

Monitor code quality over time:
- Set targets (e.g., "Reduce warnings by 50%")
- Track metrics in CI/CD
- Celebrate improvements

## Troubleshooting

### Issue: PSScriptAnalyzer Not Found

**Solution**:
```powershell
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force
```

### Issue: Too Many Warnings

**Solution**: Start with critical issues

```powershell
# Only show errors
.\Invoke-CodeQualityCheck.ps1 -Severity Error

# Exclude formatting rules temporarily
.\Invoke-CodeQualityCheck.ps1 -ExcludeRules PSAlignAssignmentStatement,PSUseConsistentIndentation,PSUseConsistentWhitespace
```

### Issue: False Positives

**Solution**: Suppress specific rules

```powershell
# In settings file
@{
    ExcludeRules = @('RuleName')
}

# Or per-function
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('RuleName', '')]
function MyFunction { }
```

### Issue: Formatting Breaks Code

**Solution**: Test after formatting

```powershell
# Format
Invoke-Formatter -ScriptDefinition $content -Settings $settings | Set-Content $file

# Test syntax
$null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $file -Raw), [ref]$null)

# Run tests
Invoke-Pester
```

## Roadmap

### Immediate (This Week)

- [x] PSScriptAnalyzer integration
- [x] Configuration file
- [x] Analysis script
- [x] Documentation
- [ ] Fix critical security issue (ConvertTo-SecureString)
- [ ] Fix high-priority issues (empty catch blocks)

### Short-Term (Next 2 Weeks)

- [ ] Auto-formatting script for bulk fixes
- [ ] Pre-commit hook template
- [ ] CI/CD pipeline integration examples
- [ ] Code quality dashboard

### Medium-Term (Next Month)

- [ ] Reduce warnings to < 500
- [ ] Custom rules for project-specific standards
- [ ] Code quality metrics tracking
- [ ] Automated formatting in CI/CD

## Resources

### Documentation

- **PSScriptAnalyzer GitHub**: https://github.com/PowerShell/PSScriptAnalyzer
- **Rule Documentation**: https://github.com/PowerShell/PSScriptAnalyzer/tree/master/RuleDocumentation
- **Best Practices**: https://poshcode.gitbook.io/powershell-practice-and-style/

### Tools

- **Invoke-CodeQualityCheck.ps1**: Main analysis script
- **PSScriptAnalyzerSettings.psd1**: Configuration file
- **Invoke-Formatter**: Auto-formatting (part of PSScriptAnalyzer)

### Commands

```powershell
# Install PSScriptAnalyzer
Install-Module PSScriptAnalyzer -Scope CurrentUser

# Get available rules
Get-ScriptAnalyzerRule

# Get approved verbs
Get-Verb

# Run analysis
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1

# Format code
Invoke-Formatter -ScriptDefinition $code -Settings .\PSScriptAnalyzerSettings.psd1
```

## Summary

PSScriptAnalyzer integration provides:
- ✅ Automated code quality checks
- ✅ Early bug detection
- ✅ Security issue identification
- ✅ Consistent code style
- ✅ CI/CD integration ready
- ✅ Comprehensive reporting

**Current Focus**: Fix 1 critical security error and 10 empty catch blocks, then address formatting with automated tools.

---

**For questions or issues**, see the [PSScriptAnalyzer documentation](https://github.com/PowerShell/PSScriptAnalyzer) or run `Get-Help Invoke-CodeQualityCheck.ps1 -Full`.

# EntraChecks Enhanced HTML Reporting Module
# Generates comprehensive HTML reports with executive dashboard

<#
.SYNOPSIS
    Generates enhanced HTML reports for EntraChecks findings.

.DESCRIPTION
    Creates interactive HTML reports with:
    - Executive dashboard with risk summary
    - Compliance framework mapping
    - Risk scoring and prioritization
    - Actionable remediation guidance
    - Interactive filtering and search
    - Professional styling for IT leadership

.NOTES
    Author: EntraChecks Team
    Version: 1.0.0
#>

# Import dependent modules
$modulePath = Split-Path -Parent $PSCommandPath
Import-Module (Join-Path $modulePath "EntraChecks-ComplianceMapping.psm1") -Force
Import-Module (Join-Path $modulePath "EntraChecks-RiskScoring.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $modulePath "EntraChecks-RemediationGuidance.psm1") -Force

#region HTML Generation Functions

function New-EnhancedHTMLReport {
    <#
    .SYNOPSIS
        Generates an enhanced HTML report with executive dashboard.

    .DESCRIPTION
        Creates a comprehensive HTML report integrating risk scoring, compliance mapping,
        and remediation guidance with interactive features.

    .PARAMETER Findings
        Array of finding objects to include in the report

    .PARAMETER OutputPath
        Path where the HTML report will be saved

    .PARAMETER TenantInfo
        Tenant information object (TenantId, TenantName, etc.)

    .PARAMETER PreviousAssessment
        Optional previous assessment data for delta comparison

    .PARAMETER IncludeSections
        Sections to include: All, Executive, Detailed, Compliance, Remediation

    .EXAMPLE
        New-EnhancedHTMLReport -Findings $findings -OutputPath "report.html" -TenantInfo $tenantInfo
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory)]
        [object]$TenantInfo,

        [object]$PreviousAssessment,

        [object]$DefenderCompliance,

        [string[]]$IncludeSections = @('All')
    )

    # Enhance findings with risk scoring, compliance mapping, and remediation
    $enhancedFindings = @()
    foreach ($finding in $Findings) {
        $enhanced = $finding |
            Add-RiskScoring |
            Add-ComplianceMapping |
            Add-RemediationGuidance
        $enhancedFindings += $enhanced
    }

    # Deduplicate findings by Description + Object to prevent repeated entries
    $seen = @{}
    $deduped = @()
    foreach ($f in $enhancedFindings) {
        $key = "$($f.Description)|$($f.Object)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $deduped += $f
        }
    }
    $enhancedFindings = $deduped

    # Calculate summaries
    $riskSummary = Get-RiskSummary -Findings $enhancedFindings
    $complianceGap = Get-ComplianceGapReport -Findings $enhancedFindings -Framework 'All'
    $quickWins = Get-QuickWins -Findings $enhancedFindings
    $prioritized = Get-PrioritizedFindings -Findings $enhancedFindings

    # Generate HTML sections
    $htmlHead = Get-HTMLHead
    $htmlNav = Get-HTMLNavigation
    $htmlExecutive = Get-ExecutiveDashboard -RiskSummary $riskSummary -ComplianceGap $complianceGap -TenantInfo $TenantInfo -DefenderCompliance $DefenderCompliance
    $htmlQuickWins = Get-QuickWinsSection -QuickWins $quickWins
    $htmlPriority = Get-PrioritySection -PrioritizedFindings $prioritized
    $htmlCompliance = Get-ComplianceSection -Findings $enhancedFindings -ComplianceGap $complianceGap -DefenderCompliance $DefenderCompliance
    $htmlDetailed = Get-DetailedFindingsSection -Findings $enhancedFindings
    $htmlJavaScript = Get-HTMLJavaScript

    # Assemble complete HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Entra ID Security Assessment - $($TenantInfo.TenantName)</title>
    $htmlHead
</head>
<body>
    $htmlNav
    <div class="container">
        <header class="report-header">
            <h1>&#128274; Microsoft Entra ID Security Assessment</h1>
            <div class="tenant-info">
                <p><strong>Tenant:</strong> $($TenantInfo.TenantName)</p>
                <p><strong>Tenant ID:</strong> $($TenantInfo.TenantId)</p>
                <p><strong>Report Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm:ss")</p>
                <p><strong>Total Findings:</strong> $($Findings.Count)</p>
            </div>
        </header>

        $htmlExecutive
        $htmlQuickWins
        $htmlPriority
        $htmlCompliance
        $htmlDetailed
    </div>
    $htmlJavaScript
</body>
</html>
"@

    # Write to file
    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Verbose "Enhanced HTML report generated: $OutputPath"

    return $OutputPath
}

function Get-HTMLHead {
    return @'
<style>
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }

    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #f5f7fa;
        color: #333;
        line-height: 1.6;
    }

    .container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
    }

    .report-header {
        background: linear-gradient(135deg, #0078d4 0%, #0053a6 100%);
        color: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }

    .report-header h1 {
        font-size: 2.5em;
        margin-bottom: 15px;
    }

    .tenant-info {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 10px;
        margin-top: 15px;
    }

    .tenant-info p {
        background: rgba(255, 255, 255, 0.2);
        padding: 10px;
        border-radius: 4px;
    }

    /* Navigation */
    .nav-bar {
        background: white;
        padding: 15px 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        position: sticky;
        top: 0;
        z-index: 1000;
        margin-bottom: 20px;
    }

    .nav-bar ul {
        list-style: none;
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
    }

    .nav-bar a {
        color: #0078d4;
        text-decoration: none;
        font-weight: 500;
        padding: 8px 15px;
        border-radius: 4px;
        transition: background 0.3s;
    }

    .nav-bar a:hover {
        background: #f0f0f0;
    }

    /* Executive Dashboard */
    .executive-dashboard {
        background: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .dashboard-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }

    .metric-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #ffffff 100%);
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid #0078d4;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }

    .metric-card.critical {
        border-left-color: #d13438;
    }

    .metric-card.high {
        border-left-color: #ff8c00;
    }

    .metric-card.medium {
        border-left-color: #ffb900;
    }

    .metric-card.low {
        border-left-color: #107c10;
    }

    .metric-value {
        font-size: 2.5em;
        font-weight: bold;
        margin: 10px 0;
    }

    .metric-label {
        font-size: 0.9em;
        color: #666;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Risk Level Badges */
    .risk-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 0.85em;
        font-weight: 600;
        text-transform: uppercase;
    }

    .risk-badge.critical {
        background: #d13438;
        color: white;
    }

    .risk-badge.high {
        background: #ff8c00;
        color: white;
    }

    .risk-badge.medium {
        background: #ffb900;
        color: #000;
    }

    .risk-badge.low {
        background: #107c10;
        color: white;
    }

    .risk-badge.info {
        background: #0078d4;
        color: white;
    }

    /* Sections */
    .section {
        background: white;
        padding: 30px;
        border-radius: 8px;
        margin-bottom: 30px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .section-title {
        font-size: 1.8em;
        margin-bottom: 20px;
        color: #0078d4;
        border-bottom: 2px solid #0078d4;
        padding-bottom: 10px;
    }

    /* Quick Wins */
    .quick-wins-grid {
        display: grid;
        gap: 15px;
        margin-top: 20px;
    }

    .quick-win-card {
        background: #fff4ce;
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid #ffb900;
    }

    .quick-win-card h3 {
        color: #333;
        margin-bottom: 10px;
    }

    .quick-win-meta {
        display: flex;
        gap: 20px;
        margin-top: 10px;
        flex-wrap: wrap;
    }

    .quick-win-meta span {
        background: white;
        padding: 5px 10px;
        border-radius: 4px;
        font-size: 0.9em;
    }

    /* Priority Table */
    .priority-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
    }

    .priority-table th {
        background: #0078d4;
        color: white;
        padding: 12px;
        text-align: left;
        font-weight: 600;
    }

    .priority-table td {
        padding: 12px;
        border-bottom: 1px solid #e0e0e0;
    }

    .priority-table tr:hover {
        background: #f5f7fa;
    }

    .priority-score {
        font-size: 1.2em;
        font-weight: bold;
        color: #0078d4;
    }

    /* Compliance Grid */
    .compliance-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
        margin-top: 20px;
    }

    .compliance-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #ffffff 100%);
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }

    .compliance-card h3 {
        color: #0078d4;
        margin-bottom: 15px;
    }

    .compliance-stat {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid #e0e0e0;
    }

    /* Detailed Findings */
    .finding-card {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        margin-bottom: 20px;
        overflow: hidden;
    }

    .finding-header {
        padding: 20px;
        background: #f5f7fa;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .finding-header:hover {
        background: #e8eef5;
    }

    .finding-title {
        font-weight: 600;
        font-size: 1.1em;
    }

    .finding-body {
        padding: 20px;
        display: none;
    }

    .finding-body.active {
        display: block;
    }

    .finding-meta {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin: 15px 0;
        padding: 15px;
        background: #f5f7fa;
        border-radius: 4px;
    }

    .remediation-steps {
        background: #e7f3ff;
        padding: 15px;
        border-radius: 4px;
        margin-top: 15px;
    }

    .remediation-steps h4 {
        color: #0078d4;
        margin-bottom: 10px;
    }

    .remediation-steps ol {
        margin-left: 20px;
    }

    .remediation-steps li {
        margin-bottom: 8px;
    }

    /* Search and Filters */
    .controls-bar {
        background: white;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }

    .controls-bar input,
    .controls-bar select {
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 4px;
        font-size: 1em;
        margin-right: 10px;
    }

    .controls-bar input {
        width: 300px;
    }

    /* Print Styles */
    @media print {
        .nav-bar,
        .controls-bar,
        .expand-all-btn {
            display: none;
        }

        .finding-body {
            display: block !important;
        }

        body {
            background: white;
        }

        .section {
            box-shadow: none;
            page-break-inside: avoid;
        }
    }

    /* Responsive */
    @media (max-width: 768px) {
        .dashboard-grid,
        .compliance-grid {
            grid-template-columns: 1fr;
        }

        .report-header h1 {
            font-size: 1.8em;
        }

        .controls-bar input {
            width: 100%;
            margin-bottom: 10px;
        }
    }

    .code-block {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 15px;
        border-radius: 4px;
        overflow-x: auto;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.9em;
        margin: 10px 0;
    }

    .expand-all-btn {
        background: #0078d4;
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 1em;
        margin-bottom: 15px;
    }

    .expand-all-btn:hover {
        background: #0053a6;
    }

    /* Category Accordions */
    .category-accordion {
        background: white;
        border: 1px solid #e0e0e0;
        border-radius: 8px;
        margin-bottom: 12px;
        overflow: hidden;
    }

    .category-header {
        padding: 16px 20px;
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        user-select: none;
        transition: background 0.2s;
    }

    .category-header:hover {
        background: linear-gradient(135deg, #e9ecef 0%, #dee2e6 100%);
    }

    .category-title {
        font-weight: 700;
        font-size: 1.15em;
        color: #333;
    }

    .category-badges {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }

    .category-badges .count-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.8em;
        font-weight: 600;
    }

    .count-badge.fail-badge { background: #d13438; color: white; }
    .count-badge.warning-badge { background: #ff8c00; color: white; }
    .count-badge.ok-badge { background: #107c10; color: white; }
    .count-badge.info-badge { background: #0078d4; color: white; }

    .category-arrow {
        font-size: 0.9em;
        transition: transform 0.2s;
        color: #666;
    }

    .category-arrow.open { transform: rotate(180deg); }

    .category-body {
        display: none;
        padding: 0 16px 16px 16px;
    }

    .category-body.active {
        display: block;
    }

    /* Status Sub-Accordions */
    .status-accordion {
        border: 1px solid #e8e8e8;
        border-radius: 6px;
        margin-top: 10px;
        overflow: hidden;
    }

    .status-header {
        padding: 12px 16px;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
        user-select: none;
        transition: background 0.2s;
    }

    .status-header:hover { opacity: 0.9; }

    .status-header.fail-header { background: #fde7e8; border-left: 4px solid #d13438; }
    .status-header.warning-header { background: #fff4ce; border-left: 4px solid #ff8c00; }
    .status-header.ok-header { background: #dff6dd; border-left: 4px solid #107c10; }
    .status-header.info-header { background: #e7f3ff; border-left: 4px solid #0078d4; }

    .status-title {
        font-weight: 600;
        font-size: 1em;
    }

    .status-arrow {
        font-size: 0.85em;
        transition: transform 0.2s;
        color: #666;
    }

    .status-arrow.open { transform: rotate(180deg); }

    .status-body {
        display: none;
        padding: 8px 12px 12px 12px;
    }

    .status-body.active {
        display: block;
    }

    /* Filter controls enhancements */
    .controls-bar {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        align-items: center;
    }

    .filter-group {
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .filter-group label {
        font-size: 0.85em;
        font-weight: 600;
        color: #555;
    }

    .controls-bar select {
        min-width: 140px;
    }

    .clear-filters-btn {
        background: #f0f0f0;
        color: #333;
        border: 1px solid #ccc;
        padding: 10px 16px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.95em;
    }

    .clear-filters-btn:hover {
        background: #e0e0e0;
    }

    .filter-count {
        font-size: 0.85em;
        color: #666;
        margin-left: auto;
    }

    /* Compliance Progress Bars (Defender for Cloud real data) */
    .compliance-source-label {
        font-size: 0.8em;
        color: #8a8886;
        margin-bottom: 15px;
        font-style: italic;
    }

    .compliance-standard-card {
        background: white;
        border: 1px solid #e1dfdd;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 15px;
    }

    .compliance-standard-card h3 {
        font-size: 1.05em;
        color: #323130;
        margin-bottom: 12px;
    }

    .compliance-progress-bar {
        background: #e1dfdd;
        border-radius: 6px;
        height: 24px;
        overflow: hidden;
        margin-bottom: 10px;
        position: relative;
    }

    .compliance-progress-fill {
        height: 100%;
        border-radius: 6px;
        transition: width 0.3s;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-size: 0.8em;
        font-weight: 600;
        min-width: 40px;
    }

    .compliance-progress-fill.high { background: #107c10; }
    .compliance-progress-fill.medium { background: #ff8c00; }
    .compliance-progress-fill.low { background: #d13438; }

    .compliance-stats-row {
        display: flex;
        gap: 20px;
        font-size: 0.85em;
        color: #605e5c;
        margin-bottom: 8px;
    }

    .compliance-stats-row span {
        display: flex;
        align-items: center;
        gap: 4px;
    }

    .stat-passed { color: #107c10; font-weight: 600; }
    .stat-failed { color: #d13438; font-weight: 600; }

    .compliance-detail-toggle {
        background: none;
        border: 1px solid #0078d4;
        color: #0078d4;
        padding: 4px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.8em;
        margin-top: 4px;
    }

    .compliance-detail-toggle:hover {
        background: #0078d4;
        color: white;
    }

    .compliance-detail-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 12px;
        font-size: 0.85em;
        display: none;
    }

    .compliance-detail-table.active {
        display: table;
    }

    .compliance-detail-table th {
        background: #f3f2f1;
        text-align: left;
        padding: 8px 12px;
        font-weight: 600;
        border-bottom: 2px solid #e1dfdd;
    }

    .compliance-detail-table td {
        padding: 6px 12px;
        border-bottom: 1px solid #f3f2f1;
    }

    .compliance-detail-table tr:hover td {
        background: #f8f8f8;
    }

    .control-status-passed { color: #107c10; font-weight: 600; }
    .control-status-failed { color: #d13438; font-weight: 600; }
    .control-status-na { color: #8a8886; }

    .compliance-fallback-note {
        font-size: 0.8em;
        color: #8a8886;
        font-style: italic;
        margin-top: 10px;
    }
</style>
'@
}

function Get-HTMLNavigation {
    return @'
<nav class="nav-bar">
    <ul>
        <li><a href="#executive">Executive Summary</a></li>
        <li><a href="#quick-wins">Quick Wins</a></li>
        <li><a href="#priority">Priority Findings</a></li>
        <li><a href="#compliance">Compliance Mapping</a></li>
        <li><a href="#detailed">Detailed Findings</a></li>
    </ul>
</nav>
'@
}

function Get-ExecutiveDashboard {
    param(
        [Parameter(Mandatory)]
        [object]$RiskSummary,

        [Parameter(Mandatory)]
        [object]$ComplianceGap,

        [Parameter(Mandatory)]
        [object]$TenantInfo,

        [object]$DefenderCompliance
    )

    # Build compliance impact section based on data source
    $hasDefenderData = ($DefenderCompliance -and
        $DefenderCompliance.Summary -and
        $DefenderCompliance.Summary.TotalStandards -gt 0)

    $complianceCards = ""
    if ($hasDefenderData) {
        # Show real Defender compliance data - up to 4 standards as summary cards
        $standardsShown = 0
        foreach ($sub in $DefenderCompliance.Subscriptions) {
            foreach ($std in $sub.Standards) {
                if ($standardsShown -ge 4) { break }
                $total = $std.PassedControls + $std.FailedControls
                $pct = if ($total -gt 0) { [math]::Round(($std.PassedControls / $total) * 100, 0) } else { 0 }
                $cardColor = if ($pct -ge 80) { '' } elseif ($pct -ge 60) { 'medium' } else { 'critical' }

                $complianceCards += @"
            <div class="metric-card $cardColor">
                <div class="metric-label">$($std.ShortName)</div>
                <div class="metric-value">$pct%</div>
                <div>$($std.PassedControls) of $total passed</div>
            </div>
"@
                $standardsShown++
            }
            if ($standardsShown -ge 4) { break }
        }
    }
    else {
        # Fallback: show subjective compliance gap counts
        $complianceCards = @"
            <div class="metric-card">
                <div class="metric-label">CIS M365 Controls</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.CIS.ControlsAffected)</div>
                <div>Controls with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">NIST CSF Functions</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.NIST.ControlsAffected)</div>
                <div>Functions with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">SOC 2 Criteria</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.SOC2.ControlsAffected)</div>
                <div>Criteria with findings</div>
            </div>

            <div class="metric-card">
                <div class="metric-label">PCI-DSS Requirements</div>
                <div class="metric-value">$($ComplianceGap.FrameworkGaps.PCIDSS.ControlsAffected)</div>
                <div>Requirements with findings</div>
            </div>
"@
    }

    return @"
<section class="executive-dashboard" id="executive">
    <h2 class="section-title">&#128202; Executive Summary</h2>

    <div class="dashboard-grid">
        <div class="metric-card critical">
            <div class="metric-label">Critical Risk</div>
            <div class="metric-value">$($RiskSummary.CriticalCount)</div>
            <div>$($RiskSummary.CriticalPercent)% of findings</div>
        </div>

        <div class="metric-card high">
            <div class="metric-label">High Risk</div>
            <div class="metric-value">$($RiskSummary.HighCount)</div>
            <div>$($RiskSummary.HighPercent)% of findings</div>
        </div>

        <div class="metric-card medium">
            <div class="metric-label">Medium Risk</div>
            <div class="metric-value">$($RiskSummary.MediumCount)</div>
            <div>$($RiskSummary.MediumPercent)% of findings</div>
        </div>

        <div class="metric-card low">
            <div class="metric-label">Quick Wins Available</div>
            <div class="metric-value">$($RiskSummary.QuickWinsCount)</div>
            <div>High impact, low effort</div>
        </div>
    </div>

    <div style="margin-top: 30px;">
        <h3>&#128200; Risk Analysis</h3>
        <p><strong>Average Risk Score:</strong> $($RiskSummary.AverageRiskScore) / 100</p>
        <p><strong>Highest Risk Score:</strong> $($RiskSummary.MaxRiskScore) / 100</p>
        <p><strong>Top Priority Items:</strong> $($RiskSummary.TopPriorityCount) findings require immediate attention</p>
    </div>

    <div style="margin-top: 30px;">
        <h3>&#128203; Compliance Impact</h3>
        <div class="dashboard-grid">
$complianceCards
        </div>
    </div>
</section>
"@
}

function Get-QuickWinsSection {
    param(
        [Parameter(Mandatory)]
        [array]$QuickWins
    )

    if ($QuickWins.Count -eq 0) {
        return @"
<section class="section" id="quick-wins">
    <h2 class="section-title">&#9889; Quick Wins</h2>
    <p>No quick wins identified - all findings require moderate to high effort.</p>
</section>
"@
    }

    $quickWinCards = ""
    $topQuickWins = $QuickWins | Select-Object -First 5

    foreach ($qw in $topQuickWins) {
        $quickWinCards += @"
<div class="quick-win-card">
    <h3>$($qw.Description -replace '<', '&lt;' -replace '>', '&gt;')</h3>
    <div class="quick-win-meta">
        <span><strong>Risk Score:</strong> <span class="risk-badge $($qw.RiskLevel.ToLower())">$($qw.RiskLevel)</span> $($qw.RiskScore)</span>
        <span><strong>Effort:</strong> $($qw.RemediationEffortDescription)</span>
        <span><strong>Priority Score:</strong> <span class="priority-score">$($qw.PriorityScore)</span></span>
    </div>
    <p style="margin-top: 10px;"><strong>Remediation:</strong> $($qw.Remediation -replace '<', '&lt;' -replace '>', '&gt;')</p>
</div>
"@
    }

    return @"
<section class="section" id="quick-wins">
    <h2 class="section-title">&#9889; Quick Wins - High Impact, Low Effort</h2>
    <p>These findings provide significant security improvements with minimal implementation time. Prioritize these for immediate action.</p>
    <div class="quick-wins-grid">
        $quickWinCards
    </div>
</section>
"@
}

function Get-PrioritySection {
    param(
        [Parameter(Mandatory)]
        [array]$PrioritizedFindings
    )

    $topFindings = $PrioritizedFindings | Select-Object -First 15
    $tableRows = ""

    $rank = 1
    foreach ($finding in $topFindings) {
        $tableRows += @"
<tr>
    <td><strong>$rank</strong></td>
    <td>$($finding.Description -replace '<', '&lt;' -replace '>', '&gt;')</td>
    <td><span class="risk-badge $($finding.RiskLevel.ToLower())">$($finding.RiskLevel)</span></td>
    <td>$($finding.RiskScore)</td>
    <td>$($finding.RemediationEffortDescription)</td>
    <td class="priority-score">$($finding.PriorityScore)</td>
</tr>
"@
        $rank++
    }

    return @"
<section class="section" id="priority">
    <h2 class="section-title">&#127919; Top Priority Findings - Recommended Remediation Order</h2>
    <p>Findings are prioritized by their Priority Score (Risk Score / Remediation Effort), providing the best return on investment.</p>

    <table class="priority-table">
        <thead>
            <tr>
                <th>Rank</th>
                <th>Finding</th>
                <th>Risk Level</th>
                <th>Risk Score</th>
                <th>Effort</th>
                <th>Priority Score</th>
            </tr>
        </thead>
        <tbody>
            $tableRows
        </tbody>
    </table>
</section>
"@
}

function Get-ComplianceSection {
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [object]$ComplianceGap,

        [object]$DefenderCompliance
    )

    # Determine if real Defender for Cloud data is available
    $hasDefenderData = ($DefenderCompliance -and
        $DefenderCompliance.Summary -and
        $DefenderCompliance.Summary.TotalStandards -gt 0)

    if ($hasDefenderData) {
        return Get-ComplianceSectionFromDefender -DefenderCompliance $DefenderCompliance
    }
    else {
        return Get-ComplianceSectionFallback -Findings $Findings -ComplianceGap $ComplianceGap
    }
}

function Get-ComplianceSectionFromDefender {
    param(
        [Parameter(Mandatory)]
        [object]$DefenderCompliance
    )

    $standardCards = ""
    $cardIndex = 0

    # Aggregate standards across subscriptions
    $standardsMap = @{}
    foreach ($sub in $DefenderCompliance.Subscriptions) {
        foreach ($std in $sub.Standards) {
            $key = $std.StandardName
            if (-not $standardsMap.ContainsKey($key)) {
                $standardsMap[$key] = @{
                    StandardName = $std.StandardName
                    ShortName = $std.ShortName
                    Framework = $std.Framework
                    PassedControls = 0
                    FailedControls = 0
                    TotalControls = 0
                    CompliancePercent = 0
                    Subscriptions = @()
                }
            }
            $standardsMap[$key].PassedControls += $std.PassedControls
            $standardsMap[$key].FailedControls += $std.FailedControls
            $standardsMap[$key].TotalControls += ($std.PassedControls + $std.FailedControls)
            $standardsMap[$key].Subscriptions += $sub.SubscriptionName
        }
    }

    # Sort standards by name
    $sortedStandards = $standardsMap.GetEnumerator() | Sort-Object { $_.Value.StandardName }

    foreach ($entry in $sortedStandards) {
        $std = $entry.Value
        $total = $std.TotalControls
        $passed = $std.PassedControls
        $failed = $std.FailedControls
        $pct = if ($total -gt 0) { [math]::Round(($passed / $total) * 100, 1) } else { 0 }

        $progressClass = if ($pct -ge 80) { 'high' } elseif ($pct -ge 60) { 'medium' } else { 'low' }
        $subList = ($std.Subscriptions | Select-Object -Unique) -join ', '

        # Get controls for this standard for the detail table
        $stdControls = @($DefenderCompliance.Controls | Where-Object {
                $_.Framework -eq $std.Framework -or $_.Framework -eq $std.ShortName
            })

        $controlRows = ""
        if ($stdControls.Count -gt 0) {
            $sortedControls = $stdControls | Sort-Object ControlId
            foreach ($ctrl in $sortedControls) {
                $statusClass = switch ($ctrl.Status) {
                    'Passed' { 'control-status-passed' }
                    'Failed' { 'control-status-failed' }
                    default { 'control-status-na' }
                }
                $titleSafe = $ctrl.ControlTitle -replace '<', '&lt;' -replace '>', '&gt;'
                $controlRows += @"
            <tr>
                <td>$($ctrl.ControlId)</td>
                <td>$titleSafe</td>
                <td class="$statusClass">$($ctrl.Status)</td>
                <td>$($ctrl.PassedResources)</td>
                <td>$($ctrl.FailedResources)</td>
            </tr>
"@
            }
        }

        $detailTable = ""
        if ($controlRows) {
            $detailTable = @"
        <button class="compliance-detail-toggle" onclick="toggleComplianceDetail(this)">Show Control Details</button>
        <table class="compliance-detail-table" id="compliance-detail-$cardIndex">
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Control</th>
                    <th>Status</th>
                    <th>Passed</th>
                    <th>Failed</th>
                </tr>
            </thead>
            <tbody>
$controlRows
            </tbody>
        </table>
"@
        }

        $standardCards += @"
    <div class="compliance-standard-card">
        <h3>$($std.StandardName -replace '<', '&lt;' -replace '>', '&gt;')</h3>
        <div class="compliance-progress-bar">
            <div class="compliance-progress-fill $progressClass" style="width: $pct%">$pct%</div>
        </div>
        <div class="compliance-stats-row">
            <span class="stat-passed">&#10003; $passed Passed</span>
            <span class="stat-failed">&#10007; $failed Failed</span>
            <span>$total Total Controls</span>
        </div>
        <div class="compliance-stats-row">
            <span>Subscriptions: $subList</span>
        </div>
$detailTable
    </div>
"@
        $cardIndex++
    }

    $totalPassed = $DefenderCompliance.Summary.PassedControls
    $totalFailed = $DefenderCompliance.Summary.FailedControls
    $totalAll = $totalPassed + $totalFailed
    $overallPct = if ($totalAll -gt 0) { [math]::Round(($totalPassed / $totalAll) * 100, 1) } else { 0 }

    return @"
<section class="section" id="compliance">
    <h2 class="section-title">&#128203; Regulatory Compliance (Defender for Cloud)</h2>
    <p class="compliance-source-label">Source: Microsoft Defender for Cloud Regulatory Compliance | $($DefenderCompliance.Summary.TotalStandards) standards across $($DefenderCompliance.Summary.TotalSubscriptions) subscription(s) | Overall: $totalPassed of $totalAll controls passed ($overallPct%)</p>

    $standardCards
</section>
"@
}

function Get-ComplianceSectionFallback {
    param(
        [Parameter(Mandatory)]
        [array]$Findings,

        [Parameter(Mandatory)]
        [object]$ComplianceGap
    )

    $cisCard = @"
<div class="compliance-card">
    <h3>CIS Microsoft 365 Foundations</h3>
    <div class="compliance-stat">
        <span>Controls Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.CIS.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.CIS_M365 }).Count)</strong></span>
    </div>
</div>
"@

    $nistCard = @"
<div class="compliance-card">
    <h3>NIST Cybersecurity Framework</h3>
    <div class="compliance-stat">
        <span>Functions Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.NIST.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.NIST_CSF }).Count)</strong></span>
    </div>
</div>
"@

    $soc2Card = @"
<div class="compliance-card">
    <h3>SOC 2 Trust Services</h3>
    <div class="compliance-stat">
        <span>Criteria Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.SOC2.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.SOC2 }).Count)</strong></span>
    </div>
</div>
"@

    $pciCard = @"
<div class="compliance-card">
    <h3>PCI-DSS v4.0.1</h3>
    <div class="compliance-stat">
        <span>Requirements Affected:</span>
        <span><strong>$($ComplianceGap.FrameworkGaps.PCIDSS.ControlsAffected)</strong></span>
    </div>
    <div class="compliance-stat">
        <span>Total Findings:</span>
        <span><strong>$(($Findings | Where-Object { $_.ComplianceMappings.PCI_DSS_4 }).Count)</strong></span>
    </div>
</div>
"@

    return @"
<section class="section" id="compliance">
    <h2 class="section-title">&#128203; Compliance Framework Mapping</h2>
    <p>This assessment maps findings to industry-standard compliance frameworks, helping you understand regulatory impact and compliance gaps.</p>

    <div class="compliance-grid">
        $cisCard
        $nistCard
        $soc2Card
        $pciCard
    </div>
    <p class="compliance-fallback-note">Based on EntraChecks assessment mapping. Enable regulatory compliance standards in Microsoft Defender for Cloud for real-time compliance data.</p>
</section>
"@
}

function Get-DetailedFindingsSection {
    param(
        [Parameter(Mandatory)]
        [array]$Findings
    )

    # Helper function to generate a single finding card with data attributes for filtering
    function Get-FindingCard {
        param($finding)

        $riskLevel = if ($finding.RiskLevel) { $finding.RiskLevel } else { 'Info' }
        $riskLower = $riskLevel.ToLower()
        $status = if ($finding.Status) { $finding.Status } else { 'INFO' }
        $statusLower = $status.ToLower()
        $category = if ($finding.Category) { $finding.Category } else { 'General' }
        $categoryLower = $category.ToLower() -replace '\s+', '-'

        $descSafe = if ($finding.Description) { $finding.Description -replace '<', '&lt;' -replace '>', '&gt;' } else { 'N/A' }
        $objSafe = if ($finding.Object) { $finding.Object -replace '<', '&lt;' -replace '>', '&gt;' } else { 'N/A' }
        $remSafe = if ($finding.Remediation) { $finding.Remediation -replace '<', '&lt;' -replace '>', '&gt;' } else { '' }

        $complianceRef = if ($finding.ComplianceReference) {
            "<p><strong>Compliance Frameworks:</strong> $($finding.ComplianceReference)</p>"
        }
        else { "" }

        $remediationGuidance = ""
        if ($finding.RemediationGuidance) {
            $rg = $finding.RemediationGuidance
            $stepsHtml = ($rg.StepsPortal | ForEach-Object { "<li>$($_ -replace '^\d+\.\s*', '')</li>" }) -join ""

            $remediationGuidance = @"
<div class="remediation-steps">
    <h4>&#128273; Remediation Steps (Azure Portal)</h4>
    <ol>
        $stepsHtml
    </ol>

    <h4 style="margin-top: 15px;">&#128187; PowerShell Remediation</h4>
    <div class="code-block">$($rg.StepsPowerShell -replace '<', '&lt;' -replace '>', '&gt;')</div>

    <p style="margin-top: 10px;"><strong>Impact:</strong> $($rg.Impact.Positive)</p>
    <p><strong>Considerations:</strong> $($rg.Impact.Negative)</p>
</div>
"@
        }

        return @"
<div class="finding-card" data-risk="$riskLower" data-status="$statusLower" data-category="$categoryLower">
    <div class="finding-header" onclick="toggleFinding(this)">
        <div>
            <span class="risk-badge $riskLower">$riskLevel</span>
            <span class="finding-title">$descSafe</span>
        </div>
        <span>&#9660;</span>
    </div>
    <div class="finding-body">
        <div class="finding-meta">
            <div><strong>Object:</strong> $objSafe</div>
            <div><strong>Risk Score:</strong> $($finding.RiskScore) / 100</div>
            <div><strong>Priority Score:</strong> $($finding.PriorityScore)</div>
            <div><strong>Remediation Effort:</strong> $($finding.RemediationEffortDescription)</div>
        </div>

        $complianceRef

        $(if ($remSafe) { "<p style='margin: 15px 0;'><strong>Quick Remediation:</strong> $remSafe</p>" })

        $remediationGuidance
    </div>
</div>
"@
    }

    # Gather unique categories and build the accordion structure
    $categoryGroups = $Findings | Group-Object {
        if ($_.Category) { $_.Category } else { 'General' }
    } | Sort-Object Name

    # Build category filter options
    $categoryOptions = ""
    foreach ($cg in $categoryGroups) {
        $catSafe = $cg.Name -replace '<', '&lt;' -replace '>', '&gt;'
        $catValue = $cg.Name.ToLower() -replace '\s+', '-'
        $categoryOptions += "            <option value=`"$catValue`">$catSafe ($($cg.Count))</option>`n"
    }

    # Build category accordions
    $categoryAccordions = ""
    $statusOrder = @('FAIL', 'WARNING', 'INFO', 'OK')

    foreach ($catGroup in $categoryGroups) {
        $catName = $catGroup.Name
        $catNameSafe = $catName -replace '<', '&lt;' -replace '>', '&gt;'
        $catValue = $catName.ToLower() -replace '\s+', '-'
        $catFindings = @($catGroup.Group)

        # Count by status for badges
        $failN = @($catFindings | Where-Object { $_.Status -eq 'FAIL' }).Count
        $warnN = @($catFindings | Where-Object { $_.Status -eq 'WARNING' }).Count
        $okN = @($catFindings | Where-Object { $_.Status -eq 'OK' }).Count
        $infoN = @($catFindings | Where-Object { $_.Status -eq 'INFO' }).Count

        $badges = ""
        if ($failN -gt 0) { $badges += "<span class='count-badge fail-badge'>$failN FAIL</span>" }
        if ($warnN -gt 0) { $badges += "<span class='count-badge warning-badge'>$warnN WARNING</span>" }
        if ($infoN -gt 0) { $badges += "<span class='count-badge info-badge'>$infoN INFO</span>" }
        if ($okN -gt 0) { $badges += "<span class='count-badge ok-badge'>$okN OK</span>" }

        # Build status sub-accordions within this category
        $statusAccordions = ""
        foreach ($st in $statusOrder) {
            $stFindings = @($catFindings | Where-Object { $_.Status -eq $st })
            if ($stFindings.Count -eq 0) { continue }

            $stLower = $st.ToLower()
            $stHeaderClass = "$stLower-header"

            # Sort findings within status by risk score descending
            $stFindings = $stFindings | Sort-Object { if ($_.RiskScore) { $_.RiskScore } else { 0 } } -Descending

            $findingCards = ""
            foreach ($f in $stFindings) {
                $findingCards += Get-FindingCard -finding $f
            }

            $statusAccordions += @"
        <div class="status-accordion" data-status="$stLower">
            <div class="status-header $stHeaderClass" onclick="toggleStatus(this)">
                <span class="status-title">$st ($($stFindings.Count))</span>
                <span class="status-arrow">&#9660;</span>
            </div>
            <div class="status-body">
                $findingCards
            </div>
        </div>
"@
        }

        $categoryAccordions += @"
    <div class="category-accordion" data-category="$catValue">
        <div class="category-header" onclick="toggleCategory(this)">
            <span class="category-title">$catNameSafe ($($catFindings.Count))</span>
            <span class="category-badges">$badges</span>
            <span class="category-arrow">&#9660;</span>
        </div>
        <div class="category-body">
            $statusAccordions
        </div>
    </div>
"@
    }

    return @"
<section class="section" id="detailed">
    <h2 class="section-title">Detailed Findings</h2>
    <div class="controls-bar">
        <input type="text" id="searchBox" placeholder="Search findings..." onkeyup="applyFilters()">
        <div class="filter-group">
            <label for="categoryFilter">Category:</label>
            <select id="categoryFilter" onchange="applyFilters()">
                <option value="all">All Categories</option>
$categoryOptions
            </select>
        </div>
        <div class="filter-group">
            <label for="statusFilter">Status:</label>
            <select id="statusFilter" onchange="applyFilters()">
                <option value="all">All Statuses</option>
                <option value="fail">FAIL</option>
                <option value="warning">WARNING</option>
                <option value="info">INFO</option>
                <option value="ok">OK</option>
            </select>
        </div>
        <div class="filter-group">
            <label for="riskFilter">Risk:</label>
            <select id="riskFilter" onchange="applyFilters()">
                <option value="all">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
        </div>
        <button class="expand-all-btn" onclick="expandAllCategories()">Expand All</button>
        <button class="expand-all-btn" onclick="collapseAllCategories()">Collapse All</button>
        <button class="clear-filters-btn" onclick="clearFilters()">Clear Filters</button>
        <span class="filter-count" id="filterCount"></span>
    </div>

    $categoryAccordions
</section>
"@
}

function Get-HTMLJavaScript {
    return @'
<script>
    function toggleComplianceDetail(btn) {
        var table = btn.nextElementSibling;
        if (table && table.classList.contains('compliance-detail-table')) {
            if (table.classList.contains('active')) {
                table.classList.remove('active');
                btn.textContent = 'Show Control Details';
            } else {
                table.classList.add('active');
                btn.textContent = 'Hide Control Details';
            }
        }
    }

    function toggleCategory(header) {
        var body = header.nextElementSibling;
        var arrow = header.querySelector('.category-arrow');
        if (body.classList.contains('active')) {
            body.classList.remove('active');
            arrow.classList.remove('open');
        } else {
            body.classList.add('active');
            arrow.classList.add('open');
        }
    }

    function toggleStatus(header) {
        var body = header.nextElementSibling;
        var arrow = header.querySelector('.status-arrow');
        if (body.classList.contains('active')) {
            body.classList.remove('active');
            arrow.classList.remove('open');
        } else {
            body.classList.add('active');
            arrow.classList.add('open');
        }
    }

    function toggleFinding(header) {
        var body = header.nextElementSibling;
        var arrow = header.querySelector('.finding-arrow');
        if (body.classList.contains('active')) {
            body.classList.remove('active');
            if (arrow) arrow.innerHTML = '&#9660;';
        } else {
            body.classList.add('active');
            if (arrow) arrow.innerHTML = '&#9650;';
        }
    }

    function expandAllCategories() {
        document.querySelectorAll('.category-body').forEach(function(b) { b.classList.add('active'); });
        document.querySelectorAll('.category-arrow').forEach(function(a) { a.classList.add('open'); });
        document.querySelectorAll('.status-body').forEach(function(b) { b.classList.add('active'); });
        document.querySelectorAll('.status-arrow').forEach(function(a) { a.classList.add('open'); });
        document.querySelectorAll('.finding-body').forEach(function(b) { b.classList.add('active'); });
        document.querySelectorAll('.finding-arrow').forEach(function(a) { a.innerHTML = '&#9650;'; });
    }

    function collapseAllCategories() {
        document.querySelectorAll('.category-body').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.category-arrow').forEach(function(a) { a.classList.remove('open'); });
        document.querySelectorAll('.status-body').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.status-arrow').forEach(function(a) { a.classList.remove('open'); });
        document.querySelectorAll('.finding-body').forEach(function(b) { b.classList.remove('active'); });
        document.querySelectorAll('.finding-arrow').forEach(function(a) { a.innerHTML = '&#9660;'; });
    }

    function applyFilters() {
        var searchTerm = document.getElementById('searchBox').value.toLowerCase();
        var categoryVal = document.getElementById('categoryFilter').value;
        var statusVal = document.getElementById('statusFilter').value;
        var riskVal = document.getElementById('riskFilter').value;

        var totalVisible = 0;
        var totalCards = 0;

        document.querySelectorAll('.finding-card').forEach(function(card) {
            totalCards++;
            var show = true;

            if (searchTerm && !card.textContent.toLowerCase().includes(searchTerm)) {
                show = false;
            }
            if (show && categoryVal !== 'all' && card.getAttribute('data-category') !== categoryVal) {
                show = false;
            }
            if (show && statusVal !== 'all' && card.getAttribute('data-status') !== statusVal) {
                show = false;
            }
            if (show && riskVal !== 'all' && card.getAttribute('data-risk') !== riskVal) {
                show = false;
            }

            card.style.display = show ? '' : 'none';
            if (show) totalVisible++;
        });

        document.querySelectorAll('.status-accordion').forEach(function(sa) {
            var visibleCards = sa.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            sa.style.display = visibleCards > 0 ? '' : 'none';
        });

        document.querySelectorAll('.category-accordion').forEach(function(ca) {
            var visibleCards = ca.querySelectorAll('.finding-card:not([style*="display: none"])').length;
            ca.style.display = visibleCards > 0 ? '' : 'none';
        });

        var countEl = document.getElementById('filterCount');
        if (searchTerm || categoryVal !== 'all' || statusVal !== 'all' || riskVal !== 'all') {
            countEl.textContent = 'Showing ' + totalVisible + ' of ' + totalCards + ' findings';
        } else {
            countEl.textContent = '';
        }

        if (searchTerm || categoryVal !== 'all' || statusVal !== 'all' || riskVal !== 'all') {
            document.querySelectorAll('.category-accordion:not([style*="display: none"]) .category-body').forEach(function(b) { b.classList.add('active'); });
            document.querySelectorAll('.category-accordion:not([style*="display: none"]) .category-arrow').forEach(function(a) { a.classList.add('open'); });
            document.querySelectorAll('.status-accordion:not([style*="display: none"]) .status-body').forEach(function(b) { b.classList.add('active'); });
            document.querySelectorAll('.status-accordion:not([style*="display: none"]) .status-arrow').forEach(function(a) { a.classList.add('open'); });
        }
    }

    function clearFilters() {
        document.getElementById('searchBox').value = '';
        document.getElementById('categoryFilter').value = 'all';
        document.getElementById('statusFilter').value = 'all';
        document.getElementById('riskFilter').value = 'all';
        applyFilters();
        collapseAllCategories();
    }

    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            var target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
</script>
'@
}

#endregion

#region Export Module Members

Export-ModuleMember -Function @(
    'New-EnhancedHTMLReport'
)

#endregion

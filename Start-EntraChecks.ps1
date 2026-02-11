<#
.SYNOPSIS
    Start-EntraChecks.ps1
    Unified orchestration script for EntraChecks compliance assessment suite

.DESCRIPTION
    This is the main entry point for the EntraChecks compliance assessment toolkit.
    It provides:
    
    - Interactive menu-driven interface
    - Modular execution (run individual modules or all)
    - Unified authentication management
    - Automatic report generation
    - Snapshot management for delta reporting
    - CI/CD automation support
    
    Use this script to run comprehensive compliance assessments across:
    - Microsoft Entra ID (Azure AD)
    - Microsoft Secure Score
    - Microsoft Defender for Cloud
    - Azure Policy
    - Microsoft Purview Compliance Manager

.PARAMETER Mode
    Execution mode:
    - Interactive: Menu-driven interface (default)
    - Quick: Run all modules with minimal prompts
    - Scheduled: Silent execution for automation

.PARAMETER TenantName
    Name of the tenant being assessed.

.PARAMETER OutputDirectory
    Base directory for all output files.

.PARAMETER Modules
    Specific modules to run. Options:
    - Core: EntraChecks core (25 checks)
    - IdentityProtection: Risk-based checks
    - Devices: Intune/device checks
    - SecureScore: Microsoft Secure Score
    - Defender: Defender for Cloud compliance
    - AzurePolicy: Azure Policy compliance
    - Purview: Compliance Manager
    - All: Run everything

.PARAMETER SkipAuthentication
    Skip authentication prompts (use existing sessions).

.PARAMETER SaveSnapshot
    Save assessment results as a snapshot after completion.

.PARAMETER CompareWithLast
    Compare results with the last snapshot.

.PARAMETER ExportFormat
    Output formats: HTML, CSV, JSON, All

.PARAMETER ConfigFile
    Path to configuration JSON file. When specified, configuration is loaded from file.
    Command-line parameters override configuration file values.

.PARAMETER Environment
    Environment name for environment-specific configuration overrides (e.g., "dev", "staging", "prod").
    Requires a corresponding config file (e.g., entrachecks.config.prod.json).

.EXAMPLE
    .\Start-EntraChecks.ps1
    # Launches interactive menu

.EXAMPLE
    .\Start-EntraChecks.ps1 -Mode Quick -TenantName "Contoso" -Modules All
    # Runs all modules with minimal prompts

.EXAMPLE
    .\Start-EntraChecks.ps1 -Mode Scheduled -Modules Core,SecureScore -SaveSnapshot
    # Automation mode with snapshot

.EXAMPLE
    .\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.json"
    # Load configuration from file

.EXAMPLE
    .\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.json" -Environment "prod"
    # Load base config with production environment overrides

.EXAMPLE
    .\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.json" -Modules Core
    # Load config but override Modules parameter (parameters take precedence)

.NOTES
    Version: 1.0.0
    Author: SolveGRC Team
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Interactive", "Quick", "Scheduled")]
    [string]$Mode = "Interactive",

    [Parameter()]
    [string]$TenantName,

    [Parameter()]
    [string]$OutputDirectory = ".\Output",

    [Parameter()]
    [ValidateSet("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview", "All")]
    [string[]]$Modules,

    [switch]$SkipAuthentication,

    [switch]$SaveSnapshot,

    [switch]$CompareWithLast,

    [Parameter()]
    [ValidateSet("HTML", "CSV", "JSON", "All")]
    [string]$ExportFormat = "All",

    [Parameter()]
    [string]$ConfigFile,

    [Parameter()]
    [string]$Environment
)

#region ==================== CONFIGURATION ====================

$script:Version = "1.0.0"
$script:ScriptRoot = $PSScriptRoot
$script:ModulesPath = Join-Path $PSScriptRoot "Modules"
$script:SnapshotsPath = Join-Path $PSScriptRoot "Snapshots"
$script:LogsPath = Join-Path $PSScriptRoot "Logs"

# Import configuration module
$configModule = Join-Path $script:ModulesPath "EntraChecks-Configuration.psm1"
if (Test-Path $configModule) {
    Import-Module $configModule -Force -ErrorAction SilentlyContinue
}

# Load configuration from file if provided
$script:Config = $null
if ($ConfigFile) {
    try {
        Write-Host "Loading configuration from: $ConfigFile" -ForegroundColor Cyan
        $script:Config = Import-Configuration -FilePath $ConfigFile -Environment $Environment
        Write-Host "Configuration loaded successfully!" -ForegroundColor Green

        # Apply configuration values (parameters override config)
        if (-not $PSBoundParameters.ContainsKey('Mode') -and $script:Config.Assessment.Mode) {
            $Mode = $script:Config.Assessment.Mode
        }

        if (-not $PSBoundParameters.ContainsKey('TenantName') -and $script:Config.Assessment.Tenant.TenantName) {
            $TenantName = $script:Config.Assessment.Tenant.TenantName
        }

        if (-not $PSBoundParameters.ContainsKey('OutputDirectory') -and $script:Config.Assessment.Output.Directory) {
            $OutputDirectory = $script:Config.Assessment.Output.Directory
        }

        if (-not $PSBoundParameters.ContainsKey('Modules') -and $script:Config.Assessment.Scope) {
            $Modules = $script:Config.Assessment.Scope
        }

        if (-not $PSBoundParameters.ContainsKey('ExportFormat') -and $script:Config.Assessment.Output.Formats) {
            # Map array to single format or "All"
            if ($script:Config.Assessment.Output.Formats.Count -gt 1) {
                $ExportFormat = "All"
            } else {
                $ExportFormat = $script:Config.Assessment.Output.Formats[0]
            }
        }

        # Update paths from config
        if ($script:Config.Logging.Directory) {
            $script:LogsPath = $script:Config.Logging.Directory
        }

        Write-Host "Configuration applied:" -ForegroundColor Yellow
        Write-Host "  Mode: $Mode" -ForegroundColor Gray
        Write-Host "  Modules: $($Modules -join ', ')" -ForegroundColor Gray
        Write-Host "  Output Directory: $OutputDirectory" -ForegroundColor Gray
        Write-Host "  Log Directory: $($script:LogsPath)" -ForegroundColor Gray
    }
    catch {
        Write-Error "Failed to load configuration: $_"
        Write-Host "Falling back to parameter-based configuration..." -ForegroundColor Yellow
    }
}

# Ensure directories exist
@($OutputDirectory, $script:SnapshotsPath, $script:LogsPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }
}

# Import logging module
$loggingModule = Join-Path $script:ModulesPath "EntraChecks-Logging.psm1"
if (Test-Path $loggingModule) {
    Import-Module $loggingModule -Force -ErrorAction SilentlyContinue
}

# Initialize logging subsystem (from config or defaults)
if ($script:Config -and $script:Config.Logging) {
    $logConfig = $script:Config.Logging
    Initialize-LoggingSubsystem `
        -LogDirectory $logConfig.Directory `
        -MinimumLevel $logConfig.MinimumLevel `
        -RetentionDays $logConfig.RetentionDays `
        -MaxFileSizeMB $logConfig.MaxFileSizeMB `
        -BufferSize $logConfig.BufferSize `
        -Targets $logConfig.Targets `
        -StructuredLogging:$logConfig.StructuredLogging
} else {
    # Fallback to defaults
    $logLevel = if ($Mode -eq 'Scheduled') { 'INFO' } else { 'INFO' }
    Initialize-LoggingSubsystem -LogDirectory $script:LogsPath -MinimumLevel $logLevel -RetentionDays 90 -StructuredLogging
}

Write-AuditLog -EventType "SessionStarted" -Description "EntraChecks session started" -Details @{
    Mode = $Mode
    Version = $script:Version
    User = $env:USERNAME
    Computer = $env:COMPUTERNAME
    ConfigFile = $(if ($ConfigFile) { $ConfigFile } else { "None" })
    Environment = $(if ($Environment) { $Environment } else { "None" })
}

# Module definitions
$script:ModuleDefinitions = @{
    Core = @{
        Name = "EntraChecks Core"
        Script = "Invoke-EntraChecks.ps1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "25 foundational Entra ID security checks"
    }
    IdentityProtection = @{
        Name = "Identity Protection"
        Module = "EntraChecks-IdentityProtection.psm1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "Risk-based identity protection checks (P2)"
    }
    Devices = @{
        Name = "Devices & Intune"
        Module = "EntraChecks-Devices.psm1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "Device compliance and management checks"
    }
    SecureScore = @{
        Name = "Microsoft Secure Score"
        Module = "EntraChecks-SecureScore.psm1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "Microsoft Secure Score integration"
    }
    Defender = @{
        Name = "Defender for Cloud"
        Module = "EntraChecks-DefenderCompliance.psm1"
        RequiresGraph = $false
        RequiresAzure = $true
        Description = "Regulatory compliance from Defender"
    }
    AzurePolicy = @{
        Name = "Azure Policy"
        Module = "EntraChecks-AzurePolicy.psm1"
        RequiresGraph = $false
        RequiresAzure = $true
        Description = "Azure Policy compliance state"
    }
    Purview = @{
        Name = "Purview Compliance"
        Module = "EntraChecks-PurviewCompliance.psm1"
        RequiresGraph = $true
        RequiresAzure = $false
        Description = "Compliance Manager assessments"
    }
}

# Required Graph scopes for all modules
$script:AllGraphScopes = @(
    "Directory.Read.All",
    "Policy.Read.All",
    "SecurityEvents.Read.All",
    "AuditLog.Read.All",
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyUser.Read.All",
    "Device.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "ComplianceManager.Read.All",
    "InformationProtectionPolicy.Read"
)

#endregion

#region ==================== DISPLAY FUNCTIONS ====================

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║   ███████╗███╗   ██╗████████╗██████╗  █████╗                     ║" -ForegroundColor Cyan
    Write-Host "  ║   ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗                    ║" -ForegroundColor Cyan
    Write-Host "  ║   █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║                    ║" -ForegroundColor Cyan
    Write-Host "  ║   ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██╔══██║                    ║" -ForegroundColor Cyan
    Write-Host "  ║   ███████╗██║ ╚████║   ██║   ██║  ██║██║  ██║                    ║" -ForegroundColor Cyan
    Write-Host "  ║   ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝                    ║" -ForegroundColor Cyan
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║              ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗     ║" -ForegroundColor Magenta
    Write-Host "  ║             ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝     ║" -ForegroundColor Magenta
    Write-Host "  ║             ██║     ███████║█████╗  ██║     █████╔╝ ███████╗     ║" -ForegroundColor Magenta
    Write-Host "  ║             ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ╚════██║     ║" -ForegroundColor Magenta
    Write-Host "  ║             ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████║     ║" -ForegroundColor Magenta
    Write-Host "  ║              ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝     ║" -ForegroundColor Magenta
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║           Unified Compliance Assessment Suite v$script:Version            ║" -ForegroundColor White
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Show-MainMenu {
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Gray
    Write-Host "  │                         MAIN MENU                               │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────────────────┤" -ForegroundColor Gray
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   [1] Quick Assessment      - Run all modules (recommended)    │" -ForegroundColor Yellow
    Write-Host "  │   [2] Select Modules        - Choose specific modules to run   │" -ForegroundColor Yellow
    Write-Host "  │   [3] View Last Results     - Open most recent reports         │" -ForegroundColor Yellow
    Write-Host "  │   [4] Compare Snapshots     - Delta reporting                  │" -ForegroundColor Yellow
    Write-Host "  │   [5] Manage Snapshots      - View/delete saved snapshots      │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   [A] Authentication        - Connect to Graph and Azure       │" -ForegroundColor Cyan
    Write-Host "  │   [S] Settings              - Configure output & preferences   │" -ForegroundColor Cyan
    Write-Host "  │   [H] Help                  - Documentation & guides           │" -ForegroundColor Cyan
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   [Q] Quit                                                     │" -ForegroundColor Gray
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    Write-Host ""
}

function Show-ModuleMenu {
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Gray
    Write-Host "  │                      SELECT MODULES                             │" -ForegroundColor White
    Write-Host "  ├─────────────────────────────────────────────────────────────────┤" -ForegroundColor Gray
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   ENTRA ID (Graph API)                                         │" -ForegroundColor Cyan
    Write-Host "  │   [1] Core Assessment       - 25 foundational checks           │" -ForegroundColor Yellow
    Write-Host "  │   [2] Identity Protection   - Risk-based checks (P2)           │" -ForegroundColor Yellow
    Write-Host "  │   [3] Devices and Intune    - Device compliance                │" -ForegroundColor Yellow
    Write-Host "  │   [4] Secure Score          - Microsoft Secure Score           │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   AZURE (ARM API)                                              │" -ForegroundColor Cyan
    Write-Host "  │   [5] Defender for Cloud    - Regulatory compliance            │" -ForegroundColor Yellow
    Write-Host "  │   [6] Azure Policy          - Policy compliance state          │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   MICROSOFT 365                                                │" -ForegroundColor Cyan
    Write-Host "  │   [7] Purview Compliance    - Compliance Manager               │" -ForegroundColor Yellow
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  │   [A] Select All            [R] Run Selected                   │" -ForegroundColor Green
    Write-Host "  │   [C] Clear Selection       [B] Back to Main Menu              │" -ForegroundColor Gray
    Write-Host "  │                                                                 │" -ForegroundColor Gray
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
    Write-Host ""
}

function Show-AuthStatus {
    Write-Host "`n  Authentication Status:" -ForegroundColor Cyan
    
    # Check Graph
    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($graphContext) {
        Write-Host "    [✓] Microsoft Graph: Connected as $($graphContext.Account)" -ForegroundColor Green
    }
    else {
        Write-Host "    [✗] Microsoft Graph: Not connected" -ForegroundColor Red
    }
    
    # Check Azure
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($azContext) {
        Write-Host "    [✓] Azure: Connected to $($azContext.Subscription.Name)" -ForegroundColor Green
    }
    else {
        Write-Host "    [✗] Azure: Not connected" -ForegroundColor Red
    }
    
    Write-Host ""
}

function Show-Progress {
    param(
        [string]$Activity,
        [int]$PercentComplete,
        [string]$Status
    )
    
    $width = 40
    $filled = [math]::Floor($width * $PercentComplete / 100)
    $empty = $width - $filled
    
    $bar = "█" * $filled + "░" * $empty
    
    Write-Host "`r  [$bar] $PercentComplete% - $Status" -NoNewline -ForegroundColor Cyan
}

#endregion

#region ==================== AUTHENTICATION ====================

function Connect-EntraChecks {
    param(
        [switch]$GraphOnly,
        [switch]$AzureOnly
    )

    Write-Host "`n[+] Authenticating..." -ForegroundColor Cyan
    Write-Log -Level INFO -Message "Starting authentication process" -Category "Authentication" -Properties @{
        GraphOnly = $GraphOnly.IsPresent
        AzureOnly = $AzureOnly.IsPresent
    }

    if (-not $AzureOnly) {
        Write-Host "    Connecting to Microsoft Graph..." -ForegroundColor Gray
        Write-Log -Level INFO -Message "Connecting to Microsoft Graph API" -Category "Authentication"

        try {
            Connect-MgGraph -Scopes $script:AllGraphScopes -NoWelcome -ErrorAction Stop
            $context = Get-MgContext
            Write-Host "    [OK] Connected as: $($context.Account)" -ForegroundColor Green

            Write-Log -Level INFO -Message "Microsoft Graph authentication successful" -Category "Authentication" -Properties @{
                Account = $context.Account
                TenantId = $context.TenantId
                Scopes = ($context.Scopes -join ', ')
            }
            Write-AuditLog -EventType "AuthenticationSuccess" -Description "Microsoft Graph authentication succeeded" -TargetObject "Microsoft Graph API" -Result "Success"
        }
        catch {
            Write-Host "    [!] Graph connection failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level ERROR -Message "Microsoft Graph authentication failed" -Category "Authentication" -ErrorRecord $_
            Write-AuditLog -EventType "AuthenticationFailure" -Description "Microsoft Graph authentication failed" -TargetObject "Microsoft Graph API" -Result "Failure"
            return $false
        }
    }

    if (-not $GraphOnly) {
        Write-Host "    Connecting to Azure..." -ForegroundColor Gray
        Write-Log -Level INFO -Message "Connecting to Azure" -Category "Authentication"

        try {
            $azContext = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $azContext) {
                Connect-AzAccount -ErrorAction Stop | Out-Null
            }
            $azContext = Get-AzContext
            Write-Host "    [OK] Connected to: $($azContext.Subscription.Name)" -ForegroundColor Green

            Write-Log -Level INFO -Message "Azure authentication successful" -Category "Authentication" -Properties @{
                Subscription = $azContext.Subscription.Name
                SubscriptionId = $azContext.Subscription.Id
                Account = $azContext.Account.Id
            }
            Write-AuditLog -EventType "AuthenticationSuccess" -Description "Azure authentication succeeded" -TargetObject "Azure ARM API" -Result "Success"
        }
        catch {
            Write-Host "    [!] Azure connection failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "    [i] Some modules (Defender, Azure Policy) will be unavailable" -ForegroundColor Gray
            Write-Log -Level WARN -Message "Azure authentication failed - some modules unavailable" -Category "Authentication" -ErrorRecord $_
            Write-AuditLog -EventType "AuthenticationFailure" -Description "Azure authentication failed" -TargetObject "Azure ARM API" -Result "Warning"
        }
    }

    return $true
}

#endregion

#region ==================== MODULE EXECUTION ====================

function Invoke-ModuleAssessment {
    param(
        [Parameter(Mandatory)]
        [string[]]$SelectedModules,
        
        [string]$TenantName,
        [string]$OutputDir
    )
    
    $results = @{
        StartTime = Get-Date
        Modules = @{}
        Errors = @()
    }
    
    $totalModules = $SelectedModules.Count
    $currentModule = 0
    
    foreach ($moduleName in $SelectedModules) {
        $currentModule++
        $percentComplete = [math]::Floor(($currentModule / $totalModules) * 100)

        $moduleDef = $script:ModuleDefinitions[$moduleName]
        Write-Host "`n[$currentModule/$totalModules] Running: $($moduleDef.Name)" -ForegroundColor Magenta
        Write-Host "    $($moduleDef.Description)" -ForegroundColor Gray

        Write-Log -Level INFO -Message "Starting module execution: $($moduleDef.Name)" -Category "ModuleExecution" -Properties @{
            ModuleName = $moduleName
            Description = $moduleDef.Description
            Progress = "$currentModule/$totalModules"
        }

        $moduleStartTime = Get-Date

        try {
            switch ($moduleName) {
                "Core" {
                    $scriptPath = Join-Path $script:ScriptRoot "Invoke-EntraChecks.ps1"
                    if (Test-Path $scriptPath) {
                        & $scriptPath -NonInteractive
                        $results.Modules.Core = @{ Success = $true }
                    }
                }
                
                "IdentityProtection" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-IdentityProtection.psm1"
                    if (Test-Path $modulePath) {
                        Import-Module $modulePath -Force
                        Invoke-IdentityProtectionChecks
                        $results.Modules.IdentityProtection = @{ Success = $true }
                    }
                }
                
                "Devices" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-Devices.psm1"
                    if (Test-Path $modulePath) {
                        Import-Module $modulePath -Force
                        Invoke-DeviceChecks
                        $results.Modules.Devices = @{ Success = $true }
                    }
                }
                
                "SecureScore" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-SecureScore.psm1"
                    if (Test-Path $modulePath) {
                        Import-Module $modulePath -Force
                        $script:SecureScoreData = Get-SecureScore -IncludeHistory
                        $results.Modules.SecureScore = @{ 
                            Success = $true 
                            Score = $script:SecureScoreData.ScorePercent
                        }
                    }
                }
                
                "Defender" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-DefenderCompliance.psm1"
                    if (Test-Path $modulePath) {
                        Import-Module $modulePath -Force
                        $script:DefenderComplianceData = Get-DefenderComplianceAssessment
                        $results.Modules.Defender = @{ 
                            Success = $true 
                            Standards = $script:DefenderComplianceData.Summary.TotalStandards
                        }
                    }
                }
                
                "AzurePolicy" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-AzurePolicy.psm1"
                    if (Test-Path $modulePath) {
                        Import-Module $modulePath -Force
                        $script:AzurePolicyData = Get-AzurePolicyComplianceAssessment
                        $results.Modules.AzurePolicy = @{ 
                            Success = $true 
                            Policies = $script:AzurePolicyData.Summary.TotalPolicies
                        }
                    }
                }
                
                "Purview" {
                    $modulePath = Join-Path $script:ModulesPath "EntraChecks-PurviewCompliance.psm1"
                    if (Test-Path $modulePath) {
                        Import-Module $modulePath -Force
                        $script:PurviewComplianceData = Get-PurviewComplianceAssessment
                        $results.Modules.Purview = @{ 
                            Success = $true 
                            Assessments = $script:PurviewComplianceData.Summary.TotalAssessments
                        }
                    }
                }
            }

            Write-Host "    [OK] Complete" -ForegroundColor Green

            $moduleDuration = (Get-Date) - $moduleStartTime
            Write-Log -Level INFO -Message "Module execution completed: $($moduleDef.Name)" -Category "ModuleExecution" -Properties @{
                ModuleName = $moduleName
                Duration = $moduleDuration.TotalSeconds
                Status = "Success"
            }
            Write-AuditLog -EventType "CheckExecuted" -Description "Module $($moduleDef.Name) executed successfully" -TargetObject $moduleName -Result "Success"
        }
        catch {
            Write-Host "    [!] Error: $($_.Exception.Message)" -ForegroundColor Red

            $moduleDuration = (Get-Date) - $moduleStartTime
            Write-Log -Level ERROR -Message "Module execution failed: $($moduleDef.Name)" -Category "ModuleExecution" -ErrorRecord $_ -Properties @{
                ModuleName = $moduleName
                Duration = $moduleDuration.TotalSeconds
            }
            Write-AuditLog -EventType "CheckExecuted" -Description "Module $($moduleDef.Name) failed" -TargetObject $moduleName -Result "Failure"

            $results.Errors += @{
                Module = $moduleName
                Error = $_.Exception.Message
            }
            $results.Modules[$moduleName] = @{ Success = $false; Error = $_.Exception.Message }
        }
    }
    
    $results.EndTime = Get-Date
    $results.Duration = $results.EndTime - $results.StartTime
    
    return $results
}

function Export-AssessmentResults {
    param(
        [string]$OutputDir,
        [string]$TenantName,
        [switch]$IncludeUnified
    )

    Write-Host "`n[+] Generating reports..." -ForegroundColor Cyan
    Write-Log -Level INFO -Message "Starting report generation" -Category "Reporting" -Properties @{
        OutputDirectory = $OutputDir
        TenantName = $TenantName
        IncludeUnified = $IncludeUnified.IsPresent
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportDir = Join-Path $OutputDir $timestamp

    if (-not (Test-Path $reportDir)) {
        New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
    }
    
    # Generate individual reports
    if ($script:SecureScoreData) {
        $ssModule = Join-Path $script:ModulesPath "EntraChecks-SecureScore.psm1"
        Import-Module $ssModule -Force
        Export-SecureScoreReport -OutputDirectory $reportDir -TenantName $TenantName
    }
    
    if ($script:DefenderComplianceData) {
        $defModule = Join-Path $script:ModulesPath "EntraChecks-DefenderCompliance.psm1"
        Import-Module $defModule -Force
        Export-DefenderComplianceReport -OutputDirectory $reportDir -TenantName $TenantName
    }
    
    if ($script:AzurePolicyData) {
        $apModule = Join-Path $script:ModulesPath "EntraChecks-AzurePolicy.psm1"
        Import-Module $apModule -Force
        Export-AzurePolicyReport -OutputDirectory $reportDir -TenantName $TenantName
    }
    
    if ($script:PurviewComplianceData) {
        $pvModule = Join-Path $script:ModulesPath "EntraChecks-PurviewCompliance.psm1"
        Import-Module $pvModule -Force
        Export-PurviewComplianceReport -OutputDirectory $reportDir -TenantName $TenantName
    }
    
    # Generate unified report if requested
    if ($IncludeUnified) {
        $compModule = Join-Path $script:ModulesPath "EntraChecks-Compliance.psm1"
        if (Test-Path $compModule) {
            Import-Module $compModule -Force
            Export-UnifiedComplianceReport `
                -OutputDirectory $reportDir `
                -TenantName $TenantName `
                -IncludeSecureScore:($null -ne $script:SecureScoreData) `
                -IncludeDefenderCompliance:($null -ne $script:DefenderComplianceData) `
                -IncludeAzurePolicy:($null -ne $script:AzurePolicyData) `
                -IncludePurviewCompliance:($null -ne $script:PurviewComplianceData) `
                -SecureScoreData $script:SecureScoreData `
                -DefenderComplianceData $script:DefenderComplianceData `
                -AzurePolicyData $script:AzurePolicyData `
                -PurviewComplianceData $script:PurviewComplianceData
        }
    }
    
    Write-Host "    [OK] Reports saved to: $reportDir" -ForegroundColor Green

    Write-Log -Level INFO -Message "Report generation completed" -Category "Reporting" -Properties @{
        ReportDirectory = $reportDir
    }
    Write-AuditLog -EventType "ReportGenerated" -Description "Assessment reports generated" -TargetObject $reportDir -Result "Success"

    return $reportDir
}

#endregion

#region ==================== INTERACTIVE MODE ====================

function Start-InteractiveMode {
    $selectedModules = @()
    $tenantName = $TenantName
    
    while ($true) {
        Show-Banner
        Show-AuthStatus
        Show-MainMenu
        
        $choice = Read-Host "  Select option"
        
        switch ($choice.ToUpper()) {
            "1" {
                # Quick Assessment - All Modules
                if (-not $tenantName) {
                    $tenantName = Read-Host "`n  Enter tenant name"
                }
                
                if (-not $SkipAuthentication) {
                    Connect-EntraChecks
                }
                
                $allModules = @("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview")
                $results = Invoke-ModuleAssessment -SelectedModules $allModules -TenantName $tenantName -OutputDir $OutputDirectory
                
                $reportDir = Export-AssessmentResults -OutputDir $OutputDirectory -TenantName $tenantName -IncludeUnified
                
                if ($SaveSnapshot -or (Read-Host "`n  Save snapshot for future comparison? (Y/N)").ToUpper() -eq "Y") {
                    $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
                    Import-Module $deltaModule -Force
                    Save-ComplianceSnapshot -OutputDirectory $script:SnapshotsPath -TenantName $tenantName `
                        -SecureScoreData $script:SecureScoreData `
                        -DefenderComplianceData $script:DefenderComplianceData `
                        -AzurePolicyData $script:AzurePolicyData `
                        -PurviewComplianceData $script:PurviewComplianceData
                }
                
                Write-Host "`n  Assessment complete! Duration: $($results.Duration.TotalMinutes.ToString('0.0')) minutes" -ForegroundColor Green
                Write-Host "  Reports saved to: $reportDir" -ForegroundColor Cyan
                
                Read-Host "`n  Press Enter to continue"
            }
            
            "2" {
                # Select Modules
                $selectedModules = @()
                $continueSelection = $true
                
                while ($continueSelection) {
                    Show-Banner
                    Show-ModuleMenu
                    
                    if ($selectedModules.Count -gt 0) {
                        Write-Host "  Selected: $($selectedModules -join ', ')" -ForegroundColor Green
                    }
                    
                    $moduleChoice = Read-Host "  Select option"
                    
                    switch ($moduleChoice.ToUpper()) {
                        "1" { if ("Core" -notin $selectedModules) { $selectedModules += "Core" } }
                        "2" { if ("IdentityProtection" -notin $selectedModules) { $selectedModules += "IdentityProtection" } }
                        "3" { if ("Devices" -notin $selectedModules) { $selectedModules += "Devices" } }
                        "4" { if ("SecureScore" -notin $selectedModules) { $selectedModules += "SecureScore" } }
                        "5" { if ("Defender" -notin $selectedModules) { $selectedModules += "Defender" } }
                        "6" { if ("AzurePolicy" -notin $selectedModules) { $selectedModules += "AzurePolicy" } }
                        "7" { if ("Purview" -notin $selectedModules) { $selectedModules += "Purview" } }
                        "A" { $selectedModules = @("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview") }
                        "C" { $selectedModules = @() }
                        "R" {
                            if ($selectedModules.Count -gt 0) {
                                if (-not $tenantName) {
                                    $tenantName = Read-Host "`n  Enter tenant name"
                                }
                                
                                if (-not $SkipAuthentication) {
                                    Connect-EntraChecks
                                }
                                
                                $results = Invoke-ModuleAssessment -SelectedModules $selectedModules -TenantName $tenantName -OutputDir $OutputDirectory
                                $reportDir = Export-AssessmentResults -OutputDir $OutputDirectory -TenantName $tenantName -IncludeUnified
                                
                                Write-Host "`n  Assessment complete!" -ForegroundColor Green
                                Read-Host "  Press Enter to continue"
                            }
                            $continueSelection = $false
                        }
                        "B" { $continueSelection = $false }
                    }
                }
            }
            
            "3" {
                # View Last Results
                $latestDir = Get-ChildItem -Path $OutputDirectory -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($latestDir) {
                    $htmlFile = Get-ChildItem -Path $latestDir.FullName -Filter "*.html" | Select-Object -First 1
                    if ($htmlFile) {
                        Start-Process $htmlFile.FullName
                    }
                    else {
                        Write-Host "`n  No HTML reports found in: $($latestDir.FullName)" -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "`n  No previous reports found." -ForegroundColor Yellow
                }
                Read-Host "`n  Press Enter to continue"
            }
            
            "4" {
                # Compare Snapshots
                $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
                if (Test-Path $deltaModule) {
                    Import-Module $deltaModule -Force
                    
                    $snapshots = Get-ComplianceSnapshots -SnapshotDirectory $script:SnapshotsPath
                    
                    if ($snapshots.Count -lt 2) {
                        Write-Host "`n  Need at least 2 snapshots for comparison." -ForegroundColor Yellow
                        Write-Host "  Found: $($snapshots.Count) snapshot(s)" -ForegroundColor Gray
                    }
                    else {
                        Write-Host "`n  Available Snapshots:" -ForegroundColor Cyan
                        $i = 1
                        foreach ($snap in $snapshots) {
                            Write-Host "    [$i] $($snap.CreatedAt) - $($snap.SnapshotId) ($($snap.TenantName))" -ForegroundColor White
                            $i++
                        }
                        
                        $baseIdx = [int](Read-Host "`n  Select BASELINE snapshot number") - 1
                        $currIdx = [int](Read-Host "  Select CURRENT snapshot number") - 1
                        
                        $baseSnapshot = Import-ComplianceSnapshot -SnapshotPath $snapshots[$baseIdx].FilePath
                        $currSnapshot = Import-ComplianceSnapshot -SnapshotPath $snapshots[$currIdx].FilePath
                        
                        $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baseSnapshot -CurrentSnapshot $currSnapshot
                        Export-DeltaReport -DeltaData $delta -OutputDirectory $OutputDirectory -TenantName $tenantName
                    }
                }
                Read-Host "`n  Press Enter to continue"
            }
            
            "5" {
                # Manage Snapshots
                $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
                if (Test-Path $deltaModule) {
                    Import-Module $deltaModule -Force
                    
                    $snapshots = Get-ComplianceSnapshots -SnapshotDirectory $script:SnapshotsPath
                    
                    Write-Host "`n  Saved Snapshots ($($snapshots.Count)):" -ForegroundColor Cyan
                    Write-Host ("  " + ("-" * 70)) -ForegroundColor Gray
                    
                    foreach ($snap in $snapshots) {
                        Write-Host "    $($snap.CreatedAt) | $($snap.SnapshotId) | $($snap.TenantName)" -ForegroundColor White
                    }
                    
                    Write-Host ("  " + ("-" * 70)) -ForegroundColor Gray
                    Write-Host "  Directory: $script:SnapshotsPath" -ForegroundColor Gray
                }
                Read-Host "`n  Press Enter to continue"
            }
            
            "A" {
                # Authentication
                Write-Host ""
                Connect-EntraChecks
                Read-Host "`n  Press Enter to continue"
            }
            
            "S" {
                # Settings
                Write-Host "`n  Current Settings:" -ForegroundColor Cyan
                Write-Host "    Output Directory: $OutputDirectory" -ForegroundColor White
                Write-Host "    Snapshots Path:   $script:SnapshotsPath" -ForegroundColor White
                Write-Host "    Tenant Name:      $(if ($tenantName) { $tenantName } else { '(not set)' })" -ForegroundColor White
                
                $newTenant = Read-Host "`n  Enter new tenant name (or press Enter to keep current)"
                if ($newTenant) { $tenantName = $newTenant }
                
                Read-Host "`n  Press Enter to continue"
            }
            
            "H" {
                # Help
                Write-Host "`n  EntraChecks Documentation" -ForegroundColor Cyan
                Write-Host "  =========================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  Available Modules:" -ForegroundColor White
                foreach ($key in $script:ModuleDefinitions.Keys) {
                    $def = $script:ModuleDefinitions[$key]
                    Write-Host "    - $($def.Name): $($def.Description)" -ForegroundColor Gray
                }
                Write-Host ""
                Write-Host "  For detailed documentation, see the README files in the Modules folder." -ForegroundColor White
                Read-Host "`n  Press Enter to continue"
            }
            
            "Q" {
                Write-Host "`n  Goodbye!" -ForegroundColor Cyan
                return
            }
        }
    }
}

#endregion

#region ==================== QUICK/SCHEDULED MODES ====================

function Start-QuickMode {
    Write-Host "`n[+] Quick Assessment Mode" -ForegroundColor Magenta
    
    if (-not $TenantName) {
        $TenantName = Read-Host "Enter tenant name"
    }
    
    if (-not $SkipAuthentication) {
        Connect-EntraChecks
    }
    
    $modulesToRun = if ($Modules -contains "All" -or -not $Modules) {
        @("Core", "IdentityProtection", "Devices", "SecureScore", "Defender", "AzurePolicy", "Purview")
    }
    else {
        $Modules
    }
    
    $results = Invoke-ModuleAssessment -SelectedModules $modulesToRun -TenantName $TenantName -OutputDir $OutputDirectory
    $reportDir = Export-AssessmentResults -OutputDir $OutputDirectory -TenantName $TenantName -IncludeUnified
    
    if ($SaveSnapshot) {
        $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
        Import-Module $deltaModule -Force
        Save-ComplianceSnapshot -OutputDirectory $script:SnapshotsPath -TenantName $TenantName `
            -SecureScoreData $script:SecureScoreData `
            -DefenderComplianceData $script:DefenderComplianceData `
            -AzurePolicyData $script:AzurePolicyData `
            -PurviewComplianceData $script:PurviewComplianceData
    }
    
    if ($CompareWithLast) {
        $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
        Import-Module $deltaModule -Force
        
        # Get the two most recent snapshots and compare them
        $snapshots = Get-ComplianceSnapshots -SnapshotDirectory $script:SnapshotsPath
        if ($snapshots -and $snapshots.Count -ge 2) {
            $currentSnap = Import-ComplianceSnapshot -SnapshotPath $snapshots[0].FilePath
            $baselineSnap = Import-ComplianceSnapshot -SnapshotPath $snapshots[1].FilePath
            $delta = Compare-ComplianceSnapshots -BaselineSnapshot $baselineSnap -CurrentSnapshot $currentSnap
            Export-DeltaReport -DeltaData $delta -OutputDirectory $OutputDirectory -TenantName $TenantName
        }
        else {
            Write-Host "[!] Need at least 2 snapshots for comparison. Save a snapshot first." -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n[+] Assessment Complete" -ForegroundColor Green
    Write-Host "    Duration: $($results.Duration.TotalMinutes.ToString('0.0')) minutes" -ForegroundColor Cyan
    Write-Host "    Reports: $reportDir" -ForegroundColor Cyan
}

function Start-ScheduledMode {
    # Silent mode for automation
    $ErrorActionPreference = "Stop"
    
    if (-not $TenantName) {
        throw "TenantName is required for scheduled mode"
    }
    
    if (-not $SkipAuthentication) {
        # In scheduled mode, use managed identity or service principal
        # This assumes pre-authenticated session
        $graphContext = Get-MgContext -ErrorAction SilentlyContinue
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
        
        if (-not $graphContext -and -not $azContext) {
            throw "No active authentication session. Use -SkipAuthentication with pre-authenticated context."
        }
    }
    
    $modulesToRun = if ($Modules -contains "All" -or -not $Modules) {
        @("Core", "SecureScore")  # Default to core modules for scheduled runs
    }
    else {
        $Modules
    }
    
    $results = Invoke-ModuleAssessment -SelectedModules $modulesToRun -TenantName $TenantName -OutputDir $OutputDirectory
    Export-AssessmentResults -OutputDir $OutputDirectory -TenantName $TenantName -IncludeUnified
    
    if ($SaveSnapshot) {
        $deltaModule = Join-Path $script:ModulesPath "EntraChecks-DeltaReporting.psm1"
        Import-Module $deltaModule -Force
        Save-ComplianceSnapshot -OutputDirectory $script:SnapshotsPath -TenantName $TenantName `
            -SecureScoreData $script:SecureScoreData `
            -DefenderComplianceData $script:DefenderComplianceData `
            -AzurePolicyData $script:AzurePolicyData `
            -PurviewComplianceData $script:PurviewComplianceData
    }
    
    # Return structured result for automation
    return @{
        Success = $results.Errors.Count -eq 0
        Duration = $results.Duration
        Modules = $results.Modules
        Errors = $results.Errors
    }
}

#endregion

#region ==================== MAIN EXECUTION ====================

# Main entry point
try {
    switch ($Mode) {
        "Interactive" {
            Start-InteractiveMode
        }
        "Quick" {
            Start-QuickMode
        }
        "Scheduled" {
            Start-ScheduledMode
        }
    }
}
catch {
    Write-Log -Level CRITICAL -Message "Unhandled error in main execution" -Category "System" -ErrorRecord $_
    throw
}
finally {
    # Cleanup and flush logs
    if (Get-Command Stop-Logging -ErrorAction SilentlyContinue) {
        Stop-Logging
    }
}

#endregion

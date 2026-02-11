# EntraChecks Configuration Management Guide

## Overview

The EntraChecks configuration management system provides enterprise-grade configuration with schema validation, environment-specific overrides, and secure credential handling. This centralized approach replaces command-line parameters for production deployments while maintaining backward compatibility.

## Features

- **Schema-Based Validation**: JSON schema validation catches configuration errors before execution
- **Environment-Specific Configs**: Separate configurations for dev, staging, production
- **Environment Variable Substitution**: Secure credential management with `${ENV:VAR_NAME}` syntax
- **Configuration Merging**: Base configuration with environment-specific overrides
- **Default Values**: Automatic application of defaults from schema
- **Comprehensive Validation**: Type checking, range validation, format validation
- **Audit Trail**: All configuration changes are logged
- **Backward Compatible**: Works alongside existing parameter-based approach

## Quick Start

### 1. Generate a Configuration Template

```powershell
# Import the configuration module
Import-Module .\Modules\EntraChecks-Configuration.psm1

# Create a configuration template
New-ConfigurationTemplate -FilePath ".\config\entrachecks.config.json" -IncludeComments

# Or create a minimal configuration
New-ConfigurationTemplate -FilePath ".\config\minimal.json" -Minimal
```

### 2. Edit the Configuration

Edit the generated `entrachecks.config.json` file:

```json
{
  "Version": "1.0.0",
  "Assessment": {
    "Scope": ["Core", "Compliance", "IdentityProtection"],
    "Output": {
      "Directory": ".\\Output",
      "Formats": ["HTML", "CSV", "JSON"]
    }
  },
  "Logging": {
    "Directory": ".\\Logs",
    "MinimumLevel": "INFO"
  },
  "ErrorHandling": {
    "MaxRetries": 3
  }
}
```

### 3. Load and Validate

```powershell
# Load configuration
$config = Import-Configuration -FilePath ".\config\entrachecks.config.json"

# Access configuration values
$scope = Get-ConfigValue -Path "Assessment.Scope"
$logLevel = Get-ConfigValue -Path "Logging.MinimumLevel" -DefaultValue "INFO"
```

## Configuration Schema

### Required Sections

All configurations must include:

- **Version**: Configuration schema version (semver format: `1.0.0`)
- **Assessment**: Assessment execution settings
- **Logging**: Logging configuration
- **ErrorHandling**: Error handling and retry settings

### Optional Sections

- **Authentication**: Authentication method and credentials
- **Performance**: Performance tuning settings
- **Notifications**: Email, Teams, Slack notifications
- **Compliance**: Compliance framework selection

## Configuration Sections

### Assessment

Controls what is assessed and where results are saved.

```json
{
  "Assessment": {
    "Scope": ["Core", "Compliance", "IdentityProtection"],
    "Mode": "Interactive",
    "Tenant": {
      "TenantId": "12345678-1234-1234-1234-123456789012",
      "TenantName": "Contoso"
    },
    "Output": {
      "Directory": ".\\Output",
      "Formats": ["HTML", "CSV", "JSON"],
      "IncludeTimestamp": true
    },
    "Exclusions": {
      "Users": ["admin@contoso.com"],
      "Groups": ["Excluded Group"],
      "Checks": ["CHECK-001"]
    }
  }
}
```

**Valid Scopes**:
- `Core` - Core identity and access checks
- `Compliance` - Compliance assessment
- `DefenderCompliance` - Microsoft Defender compliance
- `PurviewCompliance` - Microsoft Purview compliance
- `IdentityProtection` - Identity protection checks
- `SecureScore` - Microsoft Secure Score analysis
- `Devices` - Device compliance
- `Hybrid` - Hybrid identity assessment
- `AzurePolicy` - Azure Policy compliance
- `DeltaReporting` - Delta/change reporting

**Valid Modes**:
- `Interactive` - User-interactive mode with prompts
- `Scheduled` - Automated/scheduled execution
- `CI/CD` - CI/CD pipeline execution

**Valid Output Formats**:
- `HTML` - HTML report
- `CSV` - CSV data export
- `JSON` - JSON data export
- `XML` - XML data export

### Authentication

Controls authentication method and credentials.

```json
{
  "Authentication": {
    "Method": "ServicePrincipal",
    "ServicePrincipal": {
      "ClientId": "12345678-1234-1234-1234-123456789012",
      "CertificateThumbprint": "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
      "KeyVaultName": "mykeyvault",
      "SecretName": "entrachecks-secret"
    },
    "Scopes": [
      "Directory.Read.All",
      "Policy.Read.All",
      "IdentityRiskyUser.Read.All",
      "SecurityEvents.Read.All"
    ]
  }
}
```

**Valid Authentication Methods**:
- `Interactive` - Interactive browser-based authentication
- `DeviceCode` - Device code flow for headless scenarios
- `ServicePrincipal` - Service principal with certificate or secret
- `ManagedIdentity` - Azure managed identity
- `Certificate` - Certificate-based authentication

**Security Best Practices**:
- Use Service Principal or Managed Identity in production
- Store secrets in Azure Key Vault, not configuration files
- Use environment variable substitution for sensitive values
- Rotate certificates and secrets regularly

### Logging

Controls logging behavior, retention, and output.

```json
{
  "Logging": {
    "Directory": ".\\Logs",
    "MinimumLevel": "INFO",
    "Targets": ["File", "Console", "EventLog"],
    "StructuredLogging": true,
    "RetentionDays": 90,
    "MaxFileSizeMB": 100,
    "BufferSize": 100
  }
}
```

**Valid Log Levels**: `DEBUG`, `INFO`, `WARN`, `ERROR`, `CRITICAL`

**Valid Targets**: `File`, `Console`, `EventLog` (EventLog requires admin)

**Retention and Rotation**:
- `RetentionDays`: Auto-delete logs older than this (1-3650 days)
- `MaxFileSizeMB`: Auto-rotate when file exceeds this size (1-1000 MB)

### ErrorHandling

Controls retry logic, circuit breaker, and error recovery.

```json
{
  "ErrorHandling": {
    "MaxRetries": 3,
    "BaseDelaySeconds": 5,
    "ExponentialBackoff": true,
    "CircuitBreaker": {
      "Enabled": true,
      "FailureThreshold": 5,
      "TimeoutSeconds": 60,
      "HalfOpenRequests": 1
    }
  }
}
```

**Retry Settings**:
- `MaxRetries`: Maximum retry attempts (0-10)
- `BaseDelaySeconds`: Base delay between retries (1-60 seconds)
- `ExponentialBackoff`: Enable exponential backoff

**Circuit Breaker**:
- `Enabled`: Enable circuit breaker pattern
- `FailureThreshold`: Failures before opening circuit (1-20)
- `TimeoutSeconds`: How long circuit stays open (10-600 seconds)
- `HalfOpenRequests`: Test requests in half-open state (1-10)

### Performance

Controls API throttling, caching, and concurrency.

```json
{
  "Performance": {
    "MaxConcurrentRequests": 10,
    "RateLimitBuffer": 10,
    "CacheDurationMinutes": 15,
    "EnableCaching": false
  }
}
```

**Settings**:
- `MaxConcurrentRequests`: Max parallel API calls (1-50)
- `RateLimitBuffer`: Buffer for rate limits as percentage (0-50%)
- `CacheDurationMinutes`: Cache duration (0-1440 minutes)
- `EnableCaching`: Enable response caching

### Notifications

Configure notifications for assessment completion and errors.

```json
{
  "Notifications": {
    "Email": {
      "Enabled": true,
      "SMTPServer": "smtp.office365.com",
      "Port": 587,
      "From": "entrachecks@contoso.com",
      "To": ["security-team@contoso.com"],
      "UseSSL": true
    },
    "Teams": {
      "Enabled": true,
      "WebhookURL": "https://outlook.office.com/webhook/..."
    },
    "Slack": {
      "Enabled": false,
      "WebhookURL": "https://hooks.slack.com/services/..."
    }
  }
}
```

### Compliance

Select compliance frameworks for assessment.

```json
{
  "Compliance": {
    "Frameworks": ["CIS", "NIST", "ISO27001", "SOC2"],
    "CustomBenchmarks": [
      {
        "Name": "Internal Security Baseline",
        "FilePath": ".\\benchmarks\\internal.json"
      }
    ]
  }
}
```

**Built-in Frameworks**: `NIST`, `CIS`, `ISO27001`, `SOC2`, `PCI-DSS`, `HIPAA`, `GDPR`

## Environment-Specific Configuration

### Creating Environment Overrides

Create environment-specific files that merge with base configuration:

**Base Configuration**: `entrachecks.config.json`
```json
{
  "Version": "1.0.0",
  "Assessment": {
    "Scope": ["Core"],
    "Output": {
      "Directory": ".\\Output",
      "Formats": ["HTML"]
    }
  },
  "Logging": {
    "Directory": ".\\Logs",
    "MinimumLevel": "INFO"
  },
  "ErrorHandling": {
    "MaxRetries": 3
  }
}
```

**Development Override**: `entrachecks.config.dev.json`
```json
{
  "Version": "1.0.0",
  "Logging": {
    "MinimumLevel": "DEBUG"
  },
  "ErrorHandling": {
    "MaxRetries": 1
  }
}
```

**Production Override**: `entrachecks.config.prod.json`
```json
{
  "Version": "1.0.0",
  "Assessment": {
    "Scope": ["Core", "Compliance", "IdentityProtection"],
    "Mode": "Scheduled"
  },
  "Authentication": {
    "Method": "ServicePrincipal"
  },
  "Logging": {
    "RetentionDays": 180,
    "Targets": ["File", "EventLog"]
  }
}
```

### Loading Environment Configuration

```powershell
# Load with development settings
$config = Import-Configuration -FilePath ".\config\entrachecks.config.json" -Environment "dev"

# Load with production settings
$config = Import-Configuration -FilePath ".\config\entrachecks.config.json" -Environment "prod"
```

The environment-specific file is automatically merged with the base configuration.

## Environment Variable Substitution

Secure credential management using environment variables.

### Syntax

- **Basic**: `${ENV:VARIABLE_NAME}`
- **With Default**: `${ENV:VARIABLE_NAME:default_value}`

### Example Configuration

```json
{
  "Version": "1.0.0",
  "Assessment": {
    "Scope": ["Core"],
    "Tenant": {
      "TenantId": "${ENV:TENANT_ID}",
      "TenantName": "${ENV:TENANT_NAME:Contoso}"
    },
    "Output": {
      "Directory": "${ENV:OUTPUT_DIR:.\\Output}",
      "Formats": ["HTML"]
    }
  },
  "Authentication": {
    "Method": "ServicePrincipal",
    "ServicePrincipal": {
      "ClientId": "${ENV:CLIENT_ID}",
      "KeyVaultName": "${ENV:KEYVAULT_NAME}",
      "SecretName": "${ENV:SECRET_NAME:entrachecks-secret}"
    }
  },
  "Logging": {
    "Directory": "${ENV:LOG_DIR:.\\Logs}",
    "MinimumLevel": "${ENV:LOG_LEVEL:INFO}"
  },
  "ErrorHandling": {
    "MaxRetries": 3
  }
}
```

### Setting Environment Variables

**PowerShell**:
```powershell
$env:TENANT_ID = "12345678-1234-1234-1234-123456789012"
$env:CLIENT_ID = "87654321-4321-4321-4321-210987654321"
$env:KEYVAULT_NAME = "mykeyvault"
$env:LOG_LEVEL = "DEBUG"
```

**Windows (Persistent)**:
```cmd
setx TENANT_ID "12345678-1234-1234-1234-123456789012"
setx CLIENT_ID "87654321-4321-4321-4321-210987654321"
```

**Linux/macOS**:
```bash
export TENANT_ID="12345678-1234-1234-1234-123456789012"
export CLIENT_ID="87654321-4321-4321-4321-210987654321"
```

### Security Recommendations

✅ **DO**:
- Store secrets in environment variables, not config files
- Use Azure Key Vault for production secrets
- Use managed identities when running in Azure
- Provide default values for non-sensitive settings
- Use CI/CD pipeline secret management

❌ **DON'T**:
- Commit secrets to version control
- Store secrets in plain text configuration files
- Share configuration files containing secrets
- Use the same credentials across environments

## Validation

### Automatic Validation

Configuration is automatically validated when loaded:

```powershell
# This will validate and throw an error if invalid
try {
    $config = Import-Configuration -FilePath ".\config\entrachecks.config.json"
    Write-Host "Configuration is valid!"
}
catch {
    Write-Error "Configuration validation failed: $_"
}
```

### Manual Validation

Validate without loading:

```powershell
# Validate only, don't load
$config = Import-Configuration -FilePath ".\config\entrachecks.config.json" -ValidateOnly

# Or validate a configuration object
$configObject = @{
    Version = "1.0.0"
    Assessment = @{ ... }
    Logging = @{ ... }
    ErrorHandling = @{ ... }
}

$validation = Test-Configuration -ConfigObject $configObject

if ($validation.IsValid) {
    Write-Host "Configuration is valid!"
} else {
    Write-Host "Errors:"
    $validation.Errors | ForEach-Object { Write-Host "  - $_" }
}

if ($validation.Warnings.Count -gt 0) {
    Write-Host "Warnings:"
    $validation.Warnings | ForEach-Object { Write-Host "  - $_" }
}
```

### Common Validation Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Missing required field: Version | Version field missing | Add `"Version": "1.0.0"` |
| Invalid Version format | Wrong version format | Use semver: `"1.0.0"` |
| Assessment.Scope must contain at least one module | Empty or missing scope | Add valid scope: `["Core"]` |
| Invalid scope 'InvalidName' | Typo in scope name | Use valid scope names |
| Invalid TenantId format | Wrong GUID format | Use proper GUID format |
| Missing required section: Assessment.Output | Output section missing | Add Output configuration |
| MaxRetries must be between 0 and 10 | Out of range | Use value 0-10 |
| Invalid log level 'INVALID' | Wrong log level | Use: DEBUG, INFO, WARN, ERROR, CRITICAL |

## Usage Patterns

### Pattern 1: Simple Assessment with Config

```powershell
# Import modules
Import-Module .\Modules\EntraChecks-Configuration.psm1
Import-Module .\Modules\EntraChecks-Logging.psm1

# Load configuration
$config = Import-Configuration -FilePath ".\config\entrachecks.config.json"

# Initialize logging from config
Initialize-LoggingSubsystem `
    -LogDirectory $config.Logging.Directory `
    -MinimumLevel $config.Logging.MinimumLevel `
    -RetentionDays $config.Logging.RetentionDays

# Run assessment
.\Start-EntraChecks.ps1 -Scope $config.Assessment.Scope -Mode $config.Assessment.Mode
```

### Pattern 2: Environment-Specific Execution

```powershell
param(
    [ValidateSet("dev", "staging", "prod")]
    [string]$Environment = "dev"
)

# Load environment-specific configuration
$config = Import-Configuration `
    -FilePath ".\config\entrachecks.config.json" `
    -Environment $Environment

Write-Host "Running in $Environment environment"
Write-Host "Log Level: $($config.Logging.MinimumLevel)"
Write-Host "Max Retries: $($config.ErrorHandling.MaxRetries)"

# Run assessment with environment-specific settings
.\Start-EntraChecks.ps1 -Scope $config.Assessment.Scope
```

### Pattern 3: Accessing Config Values in Functions

```powershell
function Invoke-AssessmentModule {
    param([string]$ModuleName)

    # Get configuration values
    $maxRetries = Get-ConfigValue -Path "ErrorHandling.MaxRetries" -DefaultValue 3
    $logLevel = Get-ConfigValue -Path "Logging.MinimumLevel" -DefaultValue "INFO"

    Write-Log -Level INFO -Message "Executing module: $ModuleName" -Properties @{
        MaxRetries = $maxRetries
        LogLevel = $logLevel
    }

    # Execute module with retry logic from config
    Invoke-WithRetry -MaxRetries $maxRetries -ScriptBlock {
        # Module execution logic
    }
}
```

### Pattern 4: CI/CD Pipeline Integration

```yaml
# Azure DevOps Pipeline Example
steps:
  - task: PowerShell@2
    displayName: 'Run EntraChecks Assessment'
    env:
      TENANT_ID: $(TENANT_ID_SECRET)
      CLIENT_ID: $(CLIENT_ID_SECRET)
      KEYVAULT_NAME: $(KEYVAULT_NAME)
      LOG_LEVEL: 'INFO'
    inputs:
      targetType: 'inline'
      script: |
        Import-Module .\Modules\EntraChecks-Configuration.psm1
        $config = Import-Configuration -FilePath ".\config\entrachecks.config.json" -Environment "prod"
        .\Start-EntraChecks.ps1 -Scope $config.Assessment.Scope -Mode "CI/CD"
```

## Best Practices

### Configuration Management

✅ **DO**:
- Use version control for configuration files
- Create separate configs for each environment
- Use environment variable substitution for secrets
- Validate configuration before deployment
- Document custom configuration settings
- Use minimal configuration for simple scenarios

❌ **DON'T**:
- Commit secrets to version control
- Use production credentials in development
- Modify configuration during execution
- Share configuration files containing secrets
- Hard-code environment-specific values in base config

### Organization

```
config/
├── entrachecks.config.json         # Base configuration
├── entrachecks.config.dev.json     # Development overrides
├── entrachecks.config.staging.json # Staging overrides
├── entrachecks.config.prod.json    # Production overrides
├── entrachecks.minimal.json        # Minimal template
└── README.md                        # Configuration documentation
```

### Security

1. **Secrets Management**:
   - Use Azure Key Vault for production secrets
   - Use environment variables, not config files
   - Rotate secrets regularly
   - Audit secret access

2. **Access Control**:
   - Restrict config file permissions
   - Use separate credentials per environment
   - Implement least privilege access
   - Enable audit logging

3. **Validation**:
   - Always validate before loading
   - Test configuration changes in dev first
   - Use schema validation
   - Monitor configuration errors

## Troubleshooting

### Configuration Not Loading

**Problem**: `Configuration file not found`

**Solution**:
```powershell
# Check if file exists
Test-Path ".\config\entrachecks.config.json"

# Use absolute path
$configPath = Join-Path $PSScriptRoot "config\entrachecks.config.json"
Import-Configuration -FilePath $configPath
```

### Invalid JSON Format

**Problem**: `Failed to parse configuration file`

**Solution**:
- Use a JSON validator (e.g., jsonlint.com)
- Check for missing commas, brackets, or quotes
- Remove trailing commas
- Ensure proper encoding (UTF-8)

### Environment Variables Not Expanding

**Problem**: `${ENV:VAR_NAME}` appears literally in config

**Solution**:
```powershell
# Check if variable is set
$env:VAR_NAME

# Set the variable
$env:VAR_NAME = "value"

# Reload configuration
$config = Import-Configuration -FilePath $configPath
```

### Validation Errors

**Problem**: Configuration fails validation

**Solution**:
```powershell
# Get detailed validation errors
$validation = Test-Configuration -ConfigObject $configObject

# Review errors
$validation.Errors | ForEach-Object {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Review warnings
$validation.Warnings | ForEach-Object {
    Write-Host "Warning: $_" -ForegroundColor Yellow
}

# Fix issues and re-validate
```

### Configuration Values Not Found

**Problem**: `Get-ConfigValue` returns default instead of actual value

**Solution**:
```powershell
# Check if configuration is loaded
$config = Get-Configuration
if (-not $config) {
    Write-Host "Configuration not loaded!"
    Import-Configuration -FilePath $configPath
}

# Verify path exists
$config.Assessment.Scope  # Direct access to verify
Get-ConfigValue -Path "Assessment.Scope"  # Dot notation
```

## API Reference

### Import-Configuration

Loads and validates configuration from a JSON file.

```powershell
Import-Configuration -FilePath <string> [-ValidateOnly] [-Environment <string>]
```

**Parameters**:
- `FilePath` (required): Path to configuration JSON file
- `ValidateOnly` (switch): Validate without loading
- `Environment` (optional): Environment name for overrides

**Returns**: Hashtable with configuration

**Example**:
```powershell
$config = Import-Configuration -FilePath ".\config\entrachecks.config.json" -Environment "prod"
```

### Get-Configuration

Gets the currently loaded configuration.

```powershell
Get-Configuration
```

**Returns**: Hashtable with current configuration or `$null`

**Example**:
```powershell
$config = Get-Configuration
if ($config) {
    Write-Host "Config loaded: $($config.Version)"
}
```

### Get-ConfigValue

Gets a specific configuration value by path.

```powershell
Get-ConfigValue -Path <string> [-DefaultValue <object>]
```

**Parameters**:
- `Path` (required): Dot-separated path (e.g., "Logging.MinimumLevel")
- `DefaultValue` (optional): Default if path not found

**Returns**: Configuration value or default

**Example**:
```powershell
$logLevel = Get-ConfigValue -Path "Logging.MinimumLevel" -DefaultValue "INFO"
$scopes = Get-ConfigValue -Path "Assessment.Scope"
```

### Test-Configuration

Validates a configuration object against schema.

```powershell
Test-Configuration -ConfigObject <hashtable> [-Schema <hashtable>]
```

**Parameters**:
- `ConfigObject` (required): Configuration to validate
- `Schema` (optional): Custom schema (uses default if not provided)

**Returns**: PSCustomObject with `IsValid`, `Errors`, `Warnings`

**Example**:
```powershell
$validation = Test-Configuration -ConfigObject $config
if (-not $validation.IsValid) {
    $validation.Errors | Write-Error
}
```

### Export-Configuration

Exports current configuration to JSON file.

```powershell
Export-Configuration -FilePath <string> [-NoPrettyPrint]
```

**Parameters**:
- `FilePath` (required): Output file path
- `NoPrettyPrint` (switch): Compact JSON without formatting

**Example**:
```powershell
Export-Configuration -FilePath ".\config\backup.json"
```

### New-ConfigurationTemplate

Creates a configuration template file.

```powershell
New-ConfigurationTemplate -FilePath <string> [-IncludeComments] [-Minimal]
```

**Parameters**:
- `FilePath` (required): Output file path
- `IncludeComments` (switch): Include explanatory comments
- `Minimal` (switch): Create minimal config with required fields only

**Example**:
```powershell
New-ConfigurationTemplate -FilePath ".\config\template.json" -IncludeComments
New-ConfigurationTemplate -FilePath ".\config\minimal.json" -Minimal
```

### Get-ConfigurationSchema

Gets the configuration schema definition.

```powershell
Get-ConfigurationSchema
```

**Returns**: Hashtable with JSON schema

**Example**:
```powershell
$schema = Get-ConfigurationSchema
$schema.properties.Assessment.properties.Scope.items.enum  # Get valid scopes
```

## Migration from Parameters

### Before (Parameter-Based)

```powershell
.\Start-EntraChecks.ps1 `
    -Scope Core,Compliance,IdentityProtection `
    -Mode Scheduled `
    -OutputPath "C:\Output" `
    -LogLevel INFO `
    -MaxRetries 3
```

### After (Configuration-Based)

**Configuration File** (`entrachecks.config.json`):
```json
{
  "Version": "1.0.0",
  "Assessment": {
    "Scope": ["Core", "Compliance", "IdentityProtection"],
    "Mode": "Scheduled",
    "Output": {
      "Directory": "C:\\Output",
      "Formats": ["HTML", "CSV"]
    }
  },
  "Logging": {
    "Directory": "C:\\Logs",
    "MinimumLevel": "INFO"
  },
  "ErrorHandling": {
    "MaxRetries": 3
  }
}
```

**Execution**:
```powershell
Import-Module .\Modules\EntraChecks-Configuration.psm1
$config = Import-Configuration -FilePath ".\config\entrachecks.config.json"
.\Start-EntraChecks.ps1 -ConfigFile ".\config\entrachecks.config.json"
```

### Backward Compatibility

The configuration system is **fully backward compatible**. You can:
- Continue using command-line parameters
- Mix configuration file and parameters (parameters override config)
- Gradually migrate to configuration-based approach

## Additional Resources

- **Examples**: See [Example-Configuration-Usage.ps1](../Examples/Example-Configuration-Usage.ps1)
- **Schema**: Run `Get-ConfigurationSchema | ConvertTo-Json -Depth 10`
- **Module**: See [EntraChecks-Configuration.psm1](../Modules/EntraChecks-Configuration.psm1)
- **Logging Guide**: See [Logging-Guide.md](./Logging-Guide.md)
- **Retry Logic Guide**: See [Retry-Logic-Guide.md](./Retry-Logic-Guide.md)

## Support

For issues or questions:
1. Review this documentation
2. Check example usage scripts
3. Validate your configuration
4. Review error messages and logs
5. Consult the schema for valid values

---

**End of Configuration Guide**

# EntraChecks Retry Logic & Error Handling Guide

## Overview

The EntraChecks error handling subsystem provides enterprise-grade retry logic with intelligent error detection, exponential backoff, and circuit breaker patterns. This ensures robust operation in the face of transient failures, rate limiting, and network issues.

## Features

✅ **Intelligent Retry Logic**
- Automatic detection of retryable vs non-retryable errors
- Configurable retry attempts
- Custom retry patterns

✅ **Exponential Backoff**
- Prevents thundering herd problem
- Respects rate limits
- Adds random jitter for distribution

✅ **Circuit Breaker Pattern**
- Prevents cascade failures
- Automatic recovery testing
- Per-endpoint isolation

✅ **Error Categorization**
- Retryable (network, timeouts, rate limits)
- Authentication errors
- Permission errors
- Not Found errors
- Bad Request errors

✅ **Graph API Helpers**
- Pre-configured retry for Graph API
- Automatic pagination with retry
- Built-in circuit breaker

✅ **Full Logging Integration**
- All retry attempts logged
- Circuit breaker state changes tracked
- Error categorization recorded

## Quick Start

### 1. Import the Module

```powershell
Import-Module .\Modules\EntraChecks-ErrorHandling.psm1
Import-Module .\Modules\EntraChecks-Logging.psm1  # Optional but recommended

Initialize-LoggingSubsystem -LogDirectory ".\Logs"
```

### 2. Basic Retry

```powershell
# Wrap any operation with automatic retry
$result = Invoke-WithRetry -ScriptBlock {
    Get-MgUser -UserId "user@contoso.com"
} -Operation "Get User" -MaxRetries 3

# With exponential backoff
$result = Invoke-WithRetry -ScriptBlock {
    Invoke-MgGraphRequest -Uri "/users" -Method GET
} -Operation "Get Users" -MaxRetries 5 -ExponentialBackoff
```

### 3. Graph API with Retry

```powershell
# Simple Graph request with built-in retry
$user = Invoke-GraphRequestWithRetry `
    -Uri "https://graph.microsoft.com/v1.0/me"

# Paginated request with automatic retry
$allUsers = Get-AllGraphPages `
    -Uri "https://graph.microsoft.com/v1.0/users?`$top=999"
```

### 4. Circuit Breaker

```powershell
# Create circuit breaker for an endpoint
New-CircuitBreaker -Name "ConditionalAccessAPI" `
    -FailureThreshold 5 `
    -TimeoutSeconds 60

# Use with retry logic
$policies = Invoke-WithRetry -ScriptBlock {
    Get-MgIdentityConditionalAccessPolicy
} -CircuitBreakerName "ConditionalAccessAPI" -ExponentialBackoff
```

## Detailed Usage

### Invoke-WithRetry

The core retry function that wraps any operation.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ScriptBlock` | ScriptBlock | Required | The code to execute |
| `MaxRetries` | int | 3 | Maximum retry attempts |
| `BaseDelaySeconds` | int | 5 | Base delay between retries |
| `ExponentialBackoff` | switch | false | Use exponential backoff |
| `CircuitBreakerName` | string | null | Circuit breaker to use |
| `Operation` | string | "Operation" | Operation name for logging |
| `RetryableErrorPatterns` | string[] | empty | Custom retryable patterns |

**Examples:**

```powershell
# Basic retry (3 attempts, 5 second delay)
$data = Invoke-WithRetry -ScriptBlock {
    Get-DataFromAPI
} -Operation "Get Data"

# Exponential backoff (5 attempts, exponential delays)
$data = Invoke-WithRetry -ScriptBlock {
    Get-DataFromAPI
} -Operation "Get Data" `
  -MaxRetries 5 `
  -ExponentialBackoff

# With circuit breaker
$data = Invoke-WithRetry -ScriptBlock {
    Get-DataFromAPI
} -Operation "Get Data" `
  -CircuitBreakerName "DataAPI" `
  -ExponentialBackoff

# Custom retryable errors
$data = Invoke-WithRetry -ScriptBlock {
    Invoke-CustomAPI
} -Operation "Custom API" `
  -RetryableErrorPatterns @('custom.*error', 'temporary.*failure')
```

### Circuit Breaker

Circuit breakers prevent repeated calls to failing endpoints.

**States:**

- **Closed** (Normal): Operations allowed
- **Open** (Failing): Operations blocked, immediate failure
- **Half-Open** (Testing): Limited operations to test recovery

**Functions:**

```powershell
# Create circuit breaker
New-CircuitBreaker -Name "MyAPI" `
    -FailureThreshold 5 `      # Open after 5 failures
    -TimeoutSeconds 60 `        # Wait 60s before testing
    -SuccessThreshold 2         # Close after 2 successes

# Check if circuit allows operation
$canProceed = Test-CircuitBreakerState -Name "MyAPI"

# Get current state
$state = Get-CircuitBreakerState -Name "MyAPI"
Write-Host "State: $($state.State)"
Write-Host "Failures: $($state.FailureCount)"
```

**Automatic Management:**

Circuit breakers are automatically managed when used with `Invoke-WithRetry`:

```powershell
# Circuit breaker created automatically if it doesn't exist
Invoke-WithRetry -ScriptBlock {
    # Your code
} -CircuitBreakerName "AutoAPI"

# State updated automatically:
# - Success → Reset failure count (or close if half-open)
# - Failure → Increment failure count (open if threshold reached)
```

### Error Categorization

The system automatically categorizes errors for appropriate handling:

```powershell
# Get error category
try {
    throw "HTTP 429 Too Many Requests"
}
catch {
    $category = Get-ErrorCategory -ErrorRecord $_
    # Returns: "Retryable"
}

# Test if error is retryable
try {
    throw "Network timeout"
}
catch {
    $isRetryable = Test-RetryableError -ErrorRecord $_
    # Returns: $true
}
```

**Error Categories:**

| Category | Examples | Behavior |
|----------|----------|----------|
| **Retryable** | 429, 503, 504, timeout, network | Automatic retry |
| **Authentication** | AADSTS*, 401, token expired | Fail immediately |
| **Permission** | 403, access denied | Fail immediately |
| **NotFound** | 404, not found | Fail immediately |
| **BadRequest** | 400, invalid request | Fail immediately |

**Retryable Error Patterns:**

- `throttl`, `429` - Rate limiting
- `503`, `504` - Service unavailable
- `timeout` - Timeout errors
- `network` - Network errors
- `unable to connect` - Connection failures
- `temporarily unavailable` - Temporary issues

### Exponential Backoff

Exponential backoff increases delay between retries:

**Formula:** `delay = min(2^attempt × baseDelay + jitter, 300)`

**Example Delays:**
- Attempt 1: ~5 seconds
- Attempt 2: ~10 seconds
- Attempt 3: ~20 seconds
- Attempt 4: ~40 seconds
- Attempt 5: ~80 seconds (capped at 300 seconds)

**Jitter:**
Random jitter (0-10% of delay) prevents thundering herd problem.

```powershell
# Without exponential backoff
# Delays: 5s, 5s, 5s, 5s, 5s
Invoke-WithRetry -ScriptBlock { ... } -MaxRetries 5

# With exponential backoff
# Delays: 5s, 10s, 20s, 40s, 80s
Invoke-WithRetry -ScriptBlock { ... } -MaxRetries 5 -ExponentialBackoff
```

### Rate Limit Handling

The system automatically detects and respects rate limits:

**HTTP 429 Detection:**
- Detects `429 Too Many Requests`
- Parses `Retry-After` header
- Waits specified duration before retry

```powershell
# Automatic rate limit handling
$data = Invoke-WithRetry -ScriptBlock {
    Invoke-MgGraphRequest -Uri "/users" -Method GET
} -ExponentialBackoff

# If 429 encountered:
# 1. Detects rate limit
# 2. Reads Retry-After header (e.g., 120 seconds)
# 3. Waits 120 seconds
# 4. Retries request
```

### Graph API Helpers

Pre-configured functions for Graph API:

#### Invoke-GraphRequestWithRetry

Single Graph API request with retry:

```powershell
# Simple request
$user = Invoke-GraphRequestWithRetry `
    -Uri "https://graph.microsoft.com/v1.0/me"

# With method and body
$newUser = Invoke-GraphRequestWithRetry `
    -Uri "https://graph.microsoft.com/v1.0/users" `
    -Method POST `
    -Body $userObject

# Custom retries
$data = Invoke-GraphRequestWithRetry `
    -Uri "https://graph.microsoft.com/v1.0/groups" `
    -MaxRetries 5
```

#### Get-AllGraphPages

Paginated requests with automatic retry:

```powershell
# Get all users (automatic pagination)
$allUsers = Get-AllGraphPages `
    -Uri "https://graph.microsoft.com/v1.0/users?`$top=999"

# Limited pages
$firstThousand = Get-AllGraphPages `
    -Uri "https://graph.microsoft.com/v1.0/users?`$top=500" `
    -MaxPages 2

# With filter
$filteredUsers = Get-AllGraphPages `
    -Uri "https://graph.microsoft.com/v1.0/users?`$filter=accountEnabled eq true&`$top=999"
```

**Benefits:**
- Automatic retry on each page
- Circuit breaker protection
- Full logging
- Memory efficient

## Integration Patterns

### In Check Functions

```powershell
function Test-ConditionalAccessPolicies {
    Write-Log -Level INFO -Message "Checking Conditional Access policies"

    try {
        # Use retry for API call
        $policies = Invoke-WithRetry -ScriptBlock {
            Get-MgIdentityConditionalAccessPolicy
        } -Operation "Get CA Policies" `
          -MaxRetries 3 `
          -CircuitBreakerName "ConditionalAccessAPI" `
          -ExponentialBackoff

        # Process policies
        foreach ($policy in $policies) {
            # Check logic
        }

        return $policies
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to check CA policies" -ErrorRecord $_
        throw
    }
}
```

### In Modules

```powershell
# At module level
$errorHandlingModule = Join-Path $PSScriptRoot "EntraChecks-ErrorHandling.psm1"
if (Test-Path $errorHandlingModule) {
    Import-Module $errorHandlingModule -Force
}

# In functions
function Get-SecurityData {
    $data = Invoke-GraphRequestWithRetry `
        -Uri "https://graph.microsoft.com/v1.0/security/alerts" `
        -MaxRetries 5

    return $data
}
```

### Batch Operations

```powershell
# Process items with retry
$users = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/users"

foreach ($user in $users) {
    try {
        # Retry each operation
        $methods = Invoke-WithRetry -ScriptBlock {
            Get-MgUserAuthenticationMethod -UserId $user.Id
        } -Operation "Get Auth Methods" `
          -MaxRetries 3 `
          -CircuitBreakerName "AuthMethodsAPI"

        # Process methods
    }
    catch {
        Write-Log -Level WARN -Message "Failed to get auth methods for $($user.UserPrincipalName)" -ErrorRecord $_
        continue
    }
}
```

## Best Practices

### 1. Choose Appropriate Retry Counts

```powershell
# Quick operations (< 5s): 3 retries
Invoke-WithRetry -ScriptBlock { ... } -MaxRetries 3

# Normal operations: 5 retries
Invoke-WithRetry -ScriptBlock { ... } -MaxRetries 5

# Critical operations: 10 retries
Invoke-WithRetry -ScriptBlock { ... } -MaxRetries 10 -ExponentialBackoff
```

### 2. Use Exponential Backoff for Rate-Limited APIs

```powershell
# ✅ Good - Exponential backoff for rate-limited endpoints
Invoke-WithRetry -ScriptBlock {
    Get-MgUser -All
} -MaxRetries 5 -ExponentialBackoff

# ❌ Bad - Fixed delay can hammer API
Invoke-WithRetry -ScriptBlock {
    Get-MgUser -All
} -MaxRetries 10  # Without exponential backoff
```

### 3. Use Circuit Breakers for External Services

```powershell
# ✅ Good - Circuit breaker per service
Invoke-WithRetry -CircuitBreakerName "GraphAPI" ...
Invoke-WithRetry -CircuitBreakerName "AzureManagementAPI" ...
Invoke-WithRetry -CircuitBreakerName "SecurityAPI" ...

# ❌ Bad - No circuit breaker for failing service
# Will retry forever even if service is down
```

### 4. Provide Meaningful Operation Names

```powershell
# ✅ Good - Clear operation names for logs
Invoke-WithRetry -Operation "Get Conditional Access Policies" ...
Invoke-WithRetry -Operation "Update User MFA Settings" ...
Invoke-WithRetry -Operation "Check Device Compliance" ...

# ❌ Bad - Generic or missing operation names
Invoke-WithRetry -Operation "Operation" ...
Invoke-WithRetry ...  # No operation name
```

### 5. Handle Non-Retryable Errors Appropriately

```powershell
# ✅ Good - Catch and handle non-retryable errors
try {
    $user = Invoke-WithRetry -ScriptBlock {
        Get-MgUser -UserId $userId
    }
}
catch {
    $category = Get-ErrorCategory -ErrorRecord $_

    if ($category -eq "NotFound") {
        Write-Log -Level WARN -Message "User not found: $userId"
        return $null
    }
    elseif ($category -eq "Permission") {
        Write-Log -Level ERROR -Message "Insufficient permissions"
        throw "Missing required permissions"
    }
    else {
        throw
    }
}
```

## Performance Considerations

### Retry Overhead

**Without Retries:**
- Time: Operation time only
- API Calls: 1

**With Retries (3 attempts, 5s delay):**
- Best case: Operation time
- Worst case: Operation time × 3 + 10s delay
- API Calls: 1-3

**With Exponential Backoff (5 attempts):**
- Best case: Operation time
- Worst case: Operation time × 5 + ~155s delay
- API Calls: 1-5

### Circuit Breaker Benefits

**Without Circuit Breaker:**
- Failing operations: Waste time on retries
- Resource usage: High (constant retries)
- Impact: Cascade failures

**With Circuit Breaker:**
- Failing operations: Fail fast after threshold
- Resource usage: Low (no unnecessary retries)
- Impact: Isolated failures

### Recommendations

1. **Use circuit breakers** for all external API calls
2. **Start with 3 retries** and adjust based on observations
3. **Use exponential backoff** for rate-limited APIs
4. **Monitor circuit breaker states** in logs
5. **Tune failure thresholds** based on API reliability

## Troubleshooting

### Issue: Too Many Retries

**Symptom:** Operations take very long to fail

**Solution:**
```powershell
# Reduce MaxRetries
Invoke-WithRetry -ScriptBlock { ... } -MaxRetries 3  # Instead of 10

# Use circuit breaker to fail fast
Invoke-WithRetry -CircuitBreakerName "API" -MaxRetries 3
```

### Issue: Circuit Breaker Stuck Open

**Symptom:** Operations fail immediately even when service recovered

**Solution:**
```powershell
# Check circuit breaker state
$cb = Get-CircuitBreakerState -Name "API"
Write-Host "State: $($cb.State)"
Write-Host "Opened at: $($cb.OpenedAt)"

# Wait for timeout to elapse (circuit will auto-recover)
# Or adjust timeout for faster recovery:
New-CircuitBreaker -Name "API" -TimeoutSeconds 30  # Shorter timeout
```

### Issue: Non-Retryable Errors Being Retried

**Symptom:** Permission errors cause unnecessary retries

**Solution:**
```powershell
# System automatically detects permission errors as non-retryable
# But for custom errors, verify patterns:
$isRetryable = Test-RetryableError -ErrorRecord $_

# If false positive, error will be retried unnecessarily
# Log issue and update error patterns in module
```

### Issue: Rate Limits Not Respected

**Symptom:** Still hitting rate limits despite retries

**Solution:**
```powershell
# Ensure exponential backoff is enabled
Invoke-WithRetry -ExponentialBackoff  # Add this switch

# Increase base delay
Invoke-WithRetry -BaseDelaySeconds 10 -ExponentialBackoff

# Reduce concurrency in calling code
# (Don't call 100 APIs simultaneously)
```

## Monitoring

### Log Analysis

All retry operations are logged with details:

```powershell
# View retry logs
Get-Content .\Logs\entrachecks-*.log |
    Where-Object { $_ -match '\[Retry\]' } |
    ConvertFrom-Json

# Count retries by operation
Get-Content .\Logs\entrachecks-*.log |
    Where-Object { $_ -match 'Attempt \d+ of' } |
    Group-Object -Property Category |
    Select-Object Name, Count

# Find circuit breaker events
Get-Content .\Logs\entrachecks-*.log |
    Where-Object { $_ -match 'Circuit breaker' } |
    ConvertFrom-Json |
    Format-Table Timestamp, Message, Level
```

### Metrics to Track

1. **Retry Rate**: Operations requiring retry / Total operations
2. **Average Attempts**: Average retry attempts per operation
3. **Circuit Breaker Trips**: How often circuits open
4. **Recovery Time**: Time from open to closed
5. **Failure Categories**: Distribution of error types

## Integration with Existing Code

### Replace Basic Try-Catch

**Before:**
```powershell
try {
    $data = Get-MgUser -All
}
catch {
    Start-Sleep -Seconds 5
    $data = Get-MgUser -All
}
```

**After:**
```powershell
$data = Invoke-WithRetry -ScriptBlock {
    Get-MgUser -All
} -Operation "Get All Users" -MaxRetries 3 -ExponentialBackoff
```

### Replace Manual Retry Loops

**Before:**
```powershell
$maxAttempts = 3
$attempt = 0
$success = $false

while (-not $success -and $attempt -lt $maxAttempts) {
    $attempt++
    try {
        $data = Get-SomeData
        $success = $true
    }
    catch {
        if ($attempt -eq $maxAttempts) { throw }
        Start-Sleep -Seconds ($attempt * 5)
    }
}
```

**After:**
```powershell
$data = Invoke-WithRetry -ScriptBlock {
    Get-SomeData
} -Operation "Get Some Data" -MaxRetries 3 -ExponentialBackoff
```

## Conclusion

The EntraChecks retry logic provides production-grade resilience with minimal code changes. By wrapping operations with `Invoke-WithRetry` and using circuit breakers, you can handle transient failures gracefully while maintaining performance and preventing cascade failures.

For more information, see:
- [Example-Retry-Usage.ps1](../Examples/Example-Retry-Usage.ps1)
- [EntraChecks-ErrorHandling.psm1](../Modules/EntraChecks-ErrorHandling.psm1)
- [Logging-Guide.md](Logging-Guide.md)

# Configuration Guide

This guide explains all configuration options available in MiniJwt.Core and best practices for different scenarios.

## MiniJwtOptions

The `MiniJwtOptions` class provides the following configuration properties:

### SecretKey

**Type:** `string`  
**Required:** Yes  
**Default:** Empty string

The secret key used for signing JWT tokens with the HMAC-SHA256 (HS256) algorithm.

**Requirements:**
- Must be at least 32 bytes (256 bits) for HS256
- Should be a securely generated random string
- Must be kept confidential and never committed to source control

**Example:**
```csharp
options.SecretKey = "your-secret-key-at-least-32-bytes-long-for-hs256-algorithm";
```

**Security Best Practice:**
```csharp
// Load from environment variables
options.SecretKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY");

// Or from Azure Key Vault, AWS Secrets Manager, etc.
```

### Issuer

**Type:** `string`  
**Required:** No (but recommended)  
**Default:** Empty string

The issuer claim (`iss`) identifies the principal that issued the JWT. This is typically your application's name or URL.

**Example:**
```csharp
options.Issuer = "https://api.myapp.com";
// or
options.Issuer = "MyApplicationName";
```

**Validation:**
- When set, tokens will be validated to ensure they were issued by this issuer
- When empty, issuer validation is disabled

### Audience

**Type:** `string`  
**Required:** No (but recommended)  
**Default:** Empty string

The audience claim (`aud`) identifies the recipients that the JWT is intended for. This is typically your API or client application identifier.

**Example:**
```csharp
options.Audience = "https://api.myapp.com";
// or
options.Audience = "MyClientApp";
```

**Validation:**
- When set, tokens will be validated to ensure they are intended for this audience
- When empty, audience validation is disabled

### ExpirationMinutes

**Type:** `double`  
**Required:** No  
**Default:** 60 minutes

The lifetime of generated tokens in minutes. After this time, tokens will be considered expired and validation will fail.

**Example:**
```csharp
options.ExpirationMinutes = 60;        // 1 hour
options.ExpirationMinutes = 1440;      // 24 hours
options.ExpirationMinutes = 0.5;       // 30 seconds
```

**Best Practices:**
- Use shorter lifetimes (15-60 minutes) for access tokens
- Implement refresh tokens for longer sessions
- Consider your security requirements vs. user experience

## Configuration Methods

### 1. Using appsettings.json (Recommended)

**appsettings.json:**
```json
{
  "MiniJwt": {
    "SecretKey": "your-secret-key-here",
    "Issuer": "MyApp",
    "Audience": "MyClient",
    "ExpirationMinutes": 60
  }
}
```

**Program.cs:**
```csharp
builder.Services.AddMiniJwt(options =>
{
    var config = builder.Configuration.GetSection("MiniJwt");
    options.SecretKey = config["SecretKey"];
    options.Issuer = config["Issuer"];
    options.Audience = config["Audience"];
    options.ExpirationMinutes = double.Parse(config["ExpirationMinutes"] ?? "60");
});
```

### 2. Using IConfiguration Binding

```csharp
builder.Services.Configure<MiniJwtOptions>(
    builder.Configuration.GetSection("MiniJwt"));

builder.Services.AddMiniJwt(options => 
{
    // Options are bound from configuration automatically
});
```

### 3. Direct Configuration

```csharp
builder.Services.AddMiniJwt(options =>
{
    options.SecretKey = "my-secret-key-at-least-32-bytes-long";
    options.Issuer = "MyApp";
    options.Audience = "MyClient";
    options.ExpirationMinutes = 120;
});
```

### 4. Environment-Based Configuration

**appsettings.Development.json:**
```json
{
  "MiniJwt": {
    "SecretKey": "development-secret-key-at-least-32-bytes",
    "Issuer": "MyApp-Dev",
    "Audience": "MyClient-Dev",
    "ExpirationMinutes": 1440
  }
}
```

**appsettings.Production.json:**
```json
{
  "MiniJwt": {
    "SecretKey": "",
    "Issuer": "MyApp",
    "Audience": "MyClient",
    "ExpirationMinutes": 60
  }
}
```

**Program.cs (loading secret from environment):**
```csharp
builder.Services.AddMiniJwt(options =>
{
    var config = builder.Configuration.GetSection("MiniJwt");
    
    // Load secret from environment variable in production
    options.SecretKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY") 
                        ?? config["SecretKey"];
    options.Issuer = config["Issuer"];
    options.Audience = config["Audience"];
    options.ExpirationMinutes = double.Parse(config["ExpirationMinutes"] ?? "60");
});
```

## Multi-Tenant Configuration

For applications serving multiple tenants with different JWT configurations:

```csharp
public class TenantJwtService
{
    private readonly Dictionary<string, IMiniJwtService> _services = new();

    public TenantJwtService(IServiceProvider serviceProvider)
    {
        // Register services for each tenant
        _services["tenant1"] = CreateServiceForTenant("tenant1", serviceProvider);
        _services["tenant2"] = CreateServiceForTenant("tenant2", serviceProvider);
    }

    private IMiniJwtService CreateServiceForTenant(string tenantId, IServiceProvider sp)
    {
        var options = new MiniJwtOptions
        {
            SecretKey = GetSecretForTenant(tenantId),
            Issuer = $"MyApp-{tenantId}",
            Audience = $"MyClient-{tenantId}",
            ExpirationMinutes = 60
        };

        return new MiniJwtService(
            Options.CreateMonitor(Options.Create(options)),
            sp.GetRequiredService<ILogger<MiniJwtService>>(),
            new JwtSecurityTokenHandler { MapInboundClaims = false }
        );
    }

    public IMiniJwtService GetServiceForTenant(string tenantId)
    {
        return _services.TryGetValue(tenantId, out var service) 
            ? service 
            : throw new InvalidOperationException($"Unknown tenant: {tenantId}");
    }
}
```

## Configuration Validation

MiniJwt.Core includes built-in validation that runs on startup:

- Validates that `SecretKey` is not empty
- Validates that `SecretKey` is at least 32 bytes for HS256
- Validates that `ExpirationMinutes` is positive

**Validation errors will prevent application startup** when using `ValidateOnStart()` (which is enabled by default when using `AddMiniJwt`).

## Dynamic Configuration Updates

MiniJwt.Core supports runtime configuration updates using `IOptionsMonitor<MiniJwtOptions>`:

```csharp
public class ConfigurationUpdateService : IHostedService
{
    private readonly IOptionsMonitor<MiniJwtOptions> _optionsMonitor;
    private IDisposable _listener;

    public ConfigurationUpdateService(IOptionsMonitor<MiniJwtOptions> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _listener = _optionsMonitor.OnChange(options =>
        {
            Console.WriteLine("JWT configuration updated!");
            // MiniJwtService automatically picks up the changes
        });
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _listener?.Dispose();
        return Task.CompletedTask;
    }
}
```

## Common Configuration Patterns

### Short-Lived Access Tokens

```csharp
options.ExpirationMinutes = 15; // 15 minutes
```

Use with a refresh token mechanism for secure, long-lived sessions.

### Development/Testing

```csharp
#if DEBUG
options.ExpirationMinutes = 1440; // 24 hours for easier debugging
#else
options.ExpirationMinutes = 60;   // 1 hour in production
#endif
```

### API Gateway Integration

```csharp
options.Issuer = "https://api-gateway.company.com";
options.Audience = "microservice-a";
```

Each microservice can use the same issuer but different audiences.

## Next Steps

- Learn about [practical examples](examples.md)
- Read [security best practices](faq.md#security-best-practices)
- Explore [sample applications](../samples/)

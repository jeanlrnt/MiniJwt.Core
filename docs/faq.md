# Frequently Asked Questions (FAQ)

## General Questions

### What is MiniJwt.Core?

MiniJwt.Core is a lightweight JWT library for .NET that provides a simple way to generate and validate JWT tokens using attributes on your model properties. It's designed to be minimal, dependency-injection friendly, and multi-target framework compatible.

### What .NET versions are supported?

MiniJwt.Core supports:
- .NET 6.0
- .NET 7.0
- .NET 8.0
- .NET 9.0
- .NET 10.0

### Is MiniJwt.Core thread-safe?

Yes, the `MiniJwtService` implementation is thread-safe and can be registered as a singleton in the dependency injection container.

### Can I use MiniJwt.Core in production?

Yes, MiniJwt.Core is production-ready. However, always follow security best practices (see below) for key management, token lifetime, and secure communication.

## Configuration Questions

### Why does GenerateToken return null?

The most common reasons are:

1. **Secret key too short**: The `SecretKey` must be at least 32 bytes (256 bits) for HS256 algorithm
2. **Invalid configuration**: Check that your `MiniJwtOptions` are properly configured
3. **Exceptions during generation**: Enable logging to see detailed error messages

```csharp
// Ensure your secret key is long enough
options.SecretKey = "your-secret-key-at-least-32-bytes-long-for-hs256";
```

### How do I load the secret key from environment variables?

```csharp
builder.Services.AddMiniJwt(options =>
{
    options.SecretKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY") 
                        ?? throw new InvalidOperationException("JWT_SECRET_KEY not set");
    options.Issuer = builder.Configuration["MiniJwt:Issuer"];
    options.Audience = builder.Configuration["MiniJwt:Audience"];
});
```

### Can I use different configurations for different environments?

Yes, use environment-specific `appsettings.json` files:

- `appsettings.Development.json` - for development
- `appsettings.Production.json` - for production

Or use environment variables for sensitive configuration like secret keys.

### Can I change configuration at runtime?

Yes, MiniJwt.Core uses `IOptionsMonitor<MiniJwtOptions>` which supports runtime configuration updates. Changes to the configuration will be picked up automatically by the service.

## Token Generation Questions

### What claims are included in the token?

MiniJwt.Core includes:
- All properties decorated with `[MiniJwtClaim]` attribute
- Standard JWT claims: `iss` (issuer), `aud` (audience), `nbf` (not before), `exp` (expiration), `jti` (JWT ID)

### Can I add custom claims without using attributes?

Currently, MiniJwt.Core uses attributes to map properties to claims. If you need more flexibility, you can:

1. Create a wrapper payload object with attributed properties
2. Extend the library with a custom implementation
3. Use the underlying `System.IdentityModel.Tokens.Jwt` directly for advanced scenarios

### How do I set the token expiration?

Use the `ExpirationMinutes` option:

```csharp
options.ExpirationMinutes = 60;    // 1 hour
options.ExpirationMinutes = 1440;  // 24 hours
options.ExpirationMinutes = 0.5;   // 30 seconds
```

### What happens if I don't set Issuer or Audience?

If `Issuer` or `Audience` are empty strings:
- The claims won't be included in the token
- Validation for these claims will be disabled

For production use, it's **strongly recommended** to set both for proper token validation.

## Token Validation Questions

### Why does ValidateToken return null?

Common reasons:

1. **Token expired**: Check the `ExpirationMinutes` setting
2. **Wrong secret key**: Validation must use the same secret key as generation
3. **Issuer/Audience mismatch**: Ensure configuration matches between generation and validation
4. **Malformed token**: The token string may be corrupted or invalid
5. **Clock skew**: Token validation uses zero clock skew by default

Enable logging to see detailed validation error messages.

### How do I handle expired tokens?

Tokens are automatically validated for expiration. When a token expires, `ValidateToken` returns `null`. 

**Best practice:** Implement a refresh token mechanism:

```csharp
public class TokenResponse
{
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public DateTime ExpiresAt { get; set; }
}

// Store refresh tokens securely (database, Redis, etc.)
// Implement endpoint to exchange refresh token for new access token
```

### Can I validate tokens from external issuers?

MiniJwt.Core is designed for generating and validating your own tokens. To validate tokens from external issuers (e.g., Azure AD, Auth0), use the standard ASP.NET Core JWT authentication middleware with appropriate configuration.

## Security Best Practices

### How should I manage the secret key?

**DO:**
- ✅ Generate cryptographically random keys (at least 32 bytes)
- ✅ Store keys in secure secret management systems (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault)
- ✅ Use environment variables for keys, never hardcode
- ✅ Rotate keys periodically
- ✅ Use different keys for different environments

**DON'T:**
- ❌ Commit keys to source control
- ❌ Store keys in plain text in configuration files
- ❌ Use weak or predictable keys
- ❌ Share keys across unrelated applications
- ❌ Expose keys in logs or error messages

### How do I generate a secure secret key?

```bash
# Using openssl
openssl rand -base64 32

# Using PowerShell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))

# Using C#
var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
```

### What is the recommended token lifetime?

**Access Tokens:**
- Short-lived: 15-60 minutes
- Reduces the impact of token theft
- Use refresh tokens for longer sessions

**Refresh Tokens:**
- Long-lived: days to weeks
- Store securely on the backend
- Allow users to obtain new access tokens without re-authentication

### How should I transmit tokens?

**DO:**
- ✅ Use HTTPS/TLS for all communication
- ✅ Send tokens in the `Authorization` header: `Bearer {token}`
- ✅ Use secure, httpOnly cookies for web applications
- ✅ Implement token revocation mechanisms

**DON'T:**
- ❌ Send tokens in URLs (they may be logged)
- ❌ Store tokens in localStorage (vulnerable to XSS)
- ❌ Transmit tokens over unencrypted connections

### How do I implement key rotation?

Key rotation ensures compromised keys have limited impact:

```csharp
public class KeyRotationService
{
    private readonly List<MiniJwtOptions> _keyHistory = new();
    
    public void RotateKey(string newKey)
    {
        // Keep old key for validation of existing tokens
        var oldOptions = GetCurrentOptions();
        _keyHistory.Add(oldOptions);
        
        // Update to new key for generation
        UpdateOptions(new MiniJwtOptions 
        { 
            SecretKey = newKey,
            // ... other options
        });
        
        // Remove keys older than max token lifetime
        CleanupOldKeys();
    }
    
    public bool ValidateWithAnyKey(string token)
    {
        // Try current key first
        if (ValidateWithCurrentKey(token)) return true;
        
        // Fall back to historical keys
        return _keyHistory.Any(opts => ValidateWithKey(token, opts));
    }
}
```

### Should I validate tokens on every request?

**For stateless APIs:** Yes, validate the token on every request. This is the standard approach for JWT-based authentication.

**For stateful applications:** You may cache validation results in the user's session, but ensure proper session security and expiration handling.

### How do I prevent token theft?

1. **Use HTTPS**: Always transmit tokens over secure connections
2. **Short token lifetimes**: Limit the damage if tokens are stolen
3. **Token binding**: Bind tokens to specific clients or IP addresses (advanced)
4. **Refresh tokens**: Use short-lived access tokens with secure refresh mechanisms
5. **Monitoring**: Log and monitor for suspicious token usage patterns
6. **Revocation**: Implement a token revocation/blacklist mechanism if needed

### What about XSS and CSRF attacks?

**XSS (Cross-Site Scripting):**
- Don't store tokens in localStorage (use httpOnly cookies or memory)
- Sanitize all user input
- Use Content Security Policy (CSP) headers

**CSRF (Cross-Site Request Forgery):**
- When using cookies, implement CSRF protection (anti-forgery tokens)
- Using the `Authorization` header naturally protects against CSRF
- Validate the `Origin` or `Referer` headers

### Should I store tokens in a database?

**Generally no** for access tokens - JWT tokens are stateless by design.

**Consider storing:**
- Refresh tokens (with secure hashing)
- Revocation lists for specific tokens
- Audit logs of token generation

## Integration Questions

### How do I integrate with ASP.NET Core authentication?

See the [ASPNetCoreAuth sample](../samples/ASPNetCoreAuth/) for a complete example. In summary:

1. Register MiniJwt with `AddMiniJwt()`
2. Configure JWT authentication with matching parameters
3. Use `[Authorize]` attributes on controllers/endpoints
4. Generate tokens in your login endpoint

### Can I use MiniJwt.Core with Blazor?

Yes, you can use MiniJwt.Core in Blazor Server or in the API backend for Blazor WebAssembly. For Blazor WebAssembly, you'll typically:

1. Generate tokens in your API (using MiniJwt.Core)
2. Send tokens to the Blazor client
3. Include tokens in API requests from the client
4. Validate tokens in the API (using MiniJwt.Core)

### Can I use MiniJwt.Core with gRPC?

Yes, generate tokens with MiniJwt.Core and include them in gRPC metadata:

```csharp
var metadata = new Metadata
{
    { "Authorization", $"Bearer {token}" }
};

var call = client.MyRpcMethod(request, metadata);
```

Validate tokens in your gRPC service using ASP.NET Core authentication middleware.

### How do I test code that uses MiniJwt.Core?

See the [examples documentation](examples.md#unit-testing) for unit testing patterns. Key points:

- Create test instances with `NullLogger<MiniJwtService>.Instance`
- Use `Options.Create()` for test configurations
- Mock `IMiniJwtService` in your tests for isolation

## Troubleshooting

### Logging is not showing JWT errors

Ensure logging is properly configured:

```csharp
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Debug);
```

Or in `appsettings.json`:

```json
{
  "Logging": {
    "LogLevel": {
      "MiniJwt.Core": "Debug"
    }
  }
}
```

### Tokens are not validating after deployment

Common issues:
- Secret key differs between environments
- Issuer/Audience configuration mismatch
- System clock differences (ensure NTP synchronization)
- Configuration not loading correctly

### How can I debug token contents?

Visit [jwt.io](https://jwt.io/) and paste your token to decode and inspect its claims. **Never paste production tokens with real user data on public websites.**

For debugging in code:

```csharp
var handler = new JwtSecurityTokenHandler();
var jsonToken = handler.ReadToken(token) as JwtSecurityToken;
var claims = jsonToken?.Claims.ToList();
// Inspect claims for debugging
```

## Performance Questions

### What is the performance overhead?

MiniJwt.Core is very lightweight:
- Token generation: ~1-5ms depending on payload size
- Token validation: ~1-3ms
- Memory footprint: Minimal (stateless service)

The service can be safely registered as a singleton for optimal performance.

### Can MiniJwt.Core handle high load?

Yes, the service is thread-safe and designed for high-throughput scenarios. For very high loads:
- Register as singleton (recommended)
- Consider caching validation results if validating the same token multiple times
- Use connection pooling and async APIs in your application

### Should I cache tokens?

**For generation:** No need - generation is fast.

**For validation:** For the same token being validated multiple times in a short period, you can cache the validation result, but ensure:
- Cache expires before the token
- Cache is properly secured
- You handle cache invalidation correctly

## Contributing and Support

### How do I report a bug?

Open an issue on [GitHub](https://github.com/jeanlrnt/MiniJwt.Core/issues) with:
- .NET version
- MiniJwt.Core version
- Minimal reproduction code
- Expected vs actual behavior
- Any relevant logs or error messages

### How do I request a feature?

Open a feature request issue on GitHub. For better chances of implementation:
- Explain the use case and motivation
- Provide examples of how the feature would be used
- Consider if it fits the "minimal" philosophy of the library

### Can I contribute?

Yes! Contributions are welcome. Please:
- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Keep the library minimal and focused

### Where can I get help?

1. Check this FAQ
2. Review the [examples](examples.md)
3. Check existing [GitHub issues](https://github.com/jeanlrnt/MiniJwt.Core/issues)
4. Open a new issue with your question

## Additional Resources

- [Getting Started Guide](getting-started.md)
- [Configuration Guide](configuration.md)
- [Examples and Sample Applications](examples.md)
- [GitHub Repository](https://github.com/jeanlrnt/MiniJwt.Core)
- [NuGet Package](https://www.nuget.org/packages/MiniJwt.Core)

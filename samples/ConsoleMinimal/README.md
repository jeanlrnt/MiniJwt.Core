# ConsoleMinimal Sample

This is a minimal console application demonstrating basic MiniJwt.Core functionality:
- Token generation with a custom payload
- Token validation
- Token deserialization back to an object
- Token expiration handling

## Running the Sample

```bash
cd samples/ConsoleMinimal
dotnet run
```

## What It Demonstrates

1. **Configuration**: Manual setup of `MiniJwtOptions` without dependency injection
2. **Token Generation**: Creating a JWT with custom claims using the `[MiniJwtClaim]` attribute
3. **Token Validation**: Validating a token and accessing its claims via `ClaimsPrincipal`
4. **Deserialization**: Converting token claims back to a strongly-typed object
5. **Expiration**: Demonstrating that expired tokens are correctly rejected

## Expected Output

```
=== MiniJwt.Core Console Sample ===

1. Generating JWT token...
   ✅ Token generated: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

2. Validating token...
   ✅ Token is valid!
   - Subject: user123
   - Email: user@example.com
   - Role: admin

3. Validating and deserializing token...
   ✅ Token deserialized successfully!
   - UserId: user123
   - Email: user@example.com
   - Role: admin

4. Waiting for token to expire (65 seconds)...

5. Validating expired token...
   ✅ Token correctly rejected as expired!

=== Sample completed ===
```

## Key Concepts

### Manual Service Creation

Without dependency injection, you need to create the service manually:

```csharp
var options = Options.Create(new MiniJwtOptions { ... });
var tokenHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };
var jwtService = new MiniJwtService(
    Options.CreateMonitor(options),
    NullLogger<MiniJwtService>.Instance,
    tokenHandler
);
```

### Using Attributes for Claims

Define your payload model with the `[MiniJwtClaim]` attribute:

```csharp
public class UserPayload
{
    [MiniJwtClaim("sub")]
    public string UserId { get; set; }
    
    [MiniJwtClaim("email")]
    public string Email { get; set; }
}
```

This maps properties to JWT claim types.

## Related Documentation

- [Getting Started Guide](../../docs/getting-started.md)
- [Configuration Guide](../../docs/configuration.md)
- [More Examples](../../docs/examples.md)

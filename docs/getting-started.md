# Getting Started with MiniJwt.Core

MiniJwt.Core is a lightweight JWT (JSON Web Token) library for .NET that provides a simple and efficient way to generate and validate JWT tokens using attributes on your model properties.

## Installation

Install MiniJwt.Core via the .NET CLI:

```bash
dotnet add package MiniJwt.Core
```

Or via the Package Manager Console in Visual Studio:

```powershell
Install-Package MiniJwt.Core
```

## Requirements

- .NET 6.0 or higher
- Support for .NET 6.0, 7.0, 8.0, 9.0, and 10.0

## Quick Start

### 1. Define Your Payload Model

Create a model class with properties decorated with the `[MiniJwtClaim]` attribute:

```csharp
using MiniJwt.Core.Attributes;

public class UserPayload
{
    [MiniJwtClaim("sub")]
    public string UserId { get; set; }

    [MiniJwtClaim("email")]
    public string Email { get; set; }

    [MiniJwtClaim("role")]
    public string Role { get; set; }
}
```

### 2. Configure MiniJwt Options

In your `appsettings.json`:

```json
{
  "MiniJwt": {
    "SecretKey": "your-secret-key-at-least-32-bytes-long-for-hs256-algorithm",
    "Issuer": "YourAppName",
    "Audience": "YourAppClient",
    "ExpirationMinutes": 60
  }
}
```

### 3. Register MiniJwt in Dependency Injection

In your `Program.cs`:

```csharp
using MiniJwt.Core.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Register MiniJwt with configuration
builder.Services.AddMiniJwt(options =>
{
    var config = builder.Configuration.GetSection("MiniJwt");
    options.SecretKey = config["SecretKey"];
    options.Issuer = config["Issuer"];
    options.Audience = config["Audience"];
    options.ExpirationMinutes = double.Parse(config["ExpirationMinutes"] ?? "60");
});

var app = builder.Build();
app.Run();
```

### 4. Generate a Token

Inject `IMiniJwtService` into your controller or service:

```csharp
using MiniJwt.Core.Services;

public class AuthController : ControllerBase
{
    private readonly IMiniJwtService _jwtService;

    public AuthController(IMiniJwtService jwtService)
    {
        _jwtService = jwtService;
    }

    [HttpPost("login")]
    public IActionResult Login()
    {
        var payload = new UserPayload 
        { 
            UserId = "user123", 
            Email = "user@example.com",
            Role = "admin"
        };

        var token = _jwtService.GenerateToken(payload);
        
        if (token == null)
        {
            return StatusCode(500, "Failed to generate token");
        }

        return Ok(new { token });
    }
}
```

### 5. Validate a Token

```csharp
[HttpGet("protected")]
public IActionResult GetProtectedResource([FromHeader] string authorization)
{
    // Extract token from "Bearer {token}"
    var token = authorization?.Replace("Bearer ", "");
    
    var principal = _jwtService.ValidateToken(token);
    
    if (principal == null)
    {
        return Unauthorized();
    }

    // Access claims
    var userId = principal.FindFirst("sub")?.Value;
    return Ok(new { message = "Access granted", userId });
}
```

### 6. Validate and Deserialize

For direct object deserialization:

```csharp
var token = "your.jwt.token";
var user = _jwtService.ValidateAndDeserialize<UserPayload>(token);

if (user == null)
{
    // Invalid token or missing claims
    return Unauthorized();
}

// Use user.UserId, user.Email, user.Role
return Ok(user);
```

## Console Application Example

For a minimal console application without dependency injection:

```csharp
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;
using System.IdentityModel.Tokens.Jwt;

var options = new MiniJwtOptions
{
    SecretKey = "my-super-secret-key-at-least-32-bytes-long-hs256",
    Issuer = "MyConsoleApp",
    Audience = "MyConsoleClient",
    ExpirationMinutes = 60
};

// Create IOptionsMonitor for console usage
var optionsMonitor = Microsoft.Extensions.Options.Options.CreateMonitor(options);

var tokenHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };
var jwtService = new MiniJwtService(
    optionsMonitor, 
    NullLogger<MiniJwtService>.Instance,
    tokenHandler
);

// Generate token
var payload = new { sub = "user1", role = "admin" };
var token = jwtService.GenerateToken(payload);
Console.WriteLine($"Generated Token: {token}");

// Validate token
var principal = jwtService.ValidateToken(token);
if (principal != null)
{
    Console.WriteLine($"Token is valid! Subject: {principal.FindFirst("sub")?.Value}");
}
```

See the [ConsoleMinimal sample](../samples/ConsoleMinimal/) for a complete working example.

## Next Steps

- Learn about [configuration options](configuration.md)
- Explore [practical examples](examples.md)
- Read the [FAQ and best practices](faq.md)
- Check out the [sample applications](../samples/)

## Common Issues

### Token Generation Returns Null

The most common cause is a `SecretKey` that is too short. HS256 requires at least 32 bytes (256 bits). Make sure your secret key is at least 32 characters long.

### Token Validation Fails

Check that:
- The same `SecretKey` is used for both generation and validation
- The `Issuer` and `Audience` match between generation and validation
- The token has not expired
- Enable logging to see detailed error messages

## Support

If you encounter issues:
- Check the [FAQ](faq.md)
- Review the [samples](../samples/)
- Open an issue on [GitHub](https://github.com/jeanlrnt/MiniJwt.Core/issues)

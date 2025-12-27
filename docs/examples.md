# Examples

This page provides practical examples and links to runnable sample applications demonstrating MiniJwt.Core in different scenarios.

## Quick Examples

### Basic Token Generation and Validation

```csharp
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Services;

// 1. Define your payload model
public class UserClaims
{
    [MiniJwtClaim("sub")]
    public string UserId { get; set; }
    
    [MiniJwtClaim("email")]
    public string Email { get; set; }
    
    [MiniJwtClaim("role")]
    public string Role { get; set; }
}

// 2. Generate a token
var payload = new UserClaims 
{ 
    UserId = "123", 
    Email = "user@example.com",
    Role = "admin" 
};

var token = jwtService.GenerateToken(payload);

// 3. Validate the token
var principal = jwtService.ValidateToken(token);
if (principal != null)
{
    var userId = principal.FindFirst("sub")?.Value;
    Console.WriteLine($"Valid token for user: {userId}");
}
```

### Using Validate and Deserialize

```csharp
var token = "your.jwt.token.here";

// Validate and automatically deserialize to your model
var user = jwtService.ValidateAndDeserialize<UserClaims>(token);

if (user != null)
{
    Console.WriteLine($"User: {user.Email}, Role: {user.Role}");
}
else
{
    Console.WriteLine("Invalid or expired token");
}
```

## ASP.NET Core Integration

### Minimal API with Authentication

```csharp
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MiniJwt.Core.Extensions;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add MiniJwt
builder.Services.AddMiniJwt(options =>
{
    options.SecretKey = builder.Configuration["MiniJwt:SecretKey"];
    options.Issuer = builder.Configuration["MiniJwt:Issuer"];
    options.Audience = builder.Configuration["MiniJwt:Audience"];
    options.ExpirationMinutes = 60;
});

// Add JWT Authentication
var key = Encoding.UTF8.GetBytes(builder.Configuration["MiniJwt:SecretKey"]);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["MiniJwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["MiniJwt:Audience"],
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Login endpoint
app.MapPost("/login", (IMiniJwtService jwtService) =>
{
    var payload = new { sub = "user123", email = "user@example.com", role = "admin" };
    var token = jwtService.GenerateToken(payload);
    return Results.Ok(new { token });
});

// Protected endpoint
app.MapGet("/protected", () => "This is protected!")
    .RequireAuthorization();

app.Run();
```

### Controller-Based API

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MiniJwt.Core.Services;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IMiniJwtService _jwtService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IMiniJwtService jwtService, ILogger<AuthController> logger)
    {
        _jwtService = jwtService;
        _logger = logger;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // Validate credentials (implement your own logic)
        if (!ValidateCredentials(request.Username, request.Password))
        {
            return Unauthorized(new { message = "Invalid credentials" });
        }

        var payload = new UserPayload
        {
            UserId = "user123",
            Email = request.Username,
            Role = "user"
        };

        var token = _jwtService.GenerateToken(payload);
        
        if (token == null)
        {
            _logger.LogError("Failed to generate JWT token");
            return StatusCode(500, new { message = "Token generation failed" });
        }

        return Ok(new { token, expiresIn = 3600 });
    }

    [Authorize]
    [HttpGet("me")]
    public IActionResult GetCurrentUser()
    {
        var userId = User.FindFirst("sub")?.Value;
        var email = User.FindFirst("email")?.Value;
        var role = User.FindFirst("role")?.Value;

        return Ok(new { userId, email, role });
    }

    [Authorize(Roles = "admin")]
    [HttpGet("admin")]
    public IActionResult AdminOnly()
    {
        return Ok(new { message = "Admin access granted" });
    }

    private bool ValidateCredentials(string username, string password)
    {
        // WARNING: This is a placeholder. Implement real credential validation (e.g., check a user store, hash comparison, etc.).
        // For safety, the default implementation always rejects the credentials.
        return false;
    }
}

public record LoginRequest(string Username, string Password);
```

## Console Application

See [samples/ConsoleMinimal](../samples/ConsoleMinimal/) for a complete runnable example.

### Using Dependency Injection (Recommended)

```csharp
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MiniJwt.Core.Extensions;
using MiniJwt.Core.Services;

var host = Host.CreateDefaultBuilder(args)
    .ConfigureServices((context, services) =>
    {
        services.AddMiniJwt(options =>
        {
            options.SecretKey = "super-secret-key-at-least-32-bytes-long-hs256";
            options.Issuer = "ConsoleApp";
            options.Audience = "ConsoleClient";
            options.ExpirationMinutes = 1;
        });
    })
    .Build();

var jwtService = host.Services.GetRequiredService<IMiniJwtService>();

// Generate token
var token = jwtService.GenerateToken(new { sub = "user1", role = "admin" });
Console.WriteLine($"Token: {token}");

// Validate immediately
var principal = jwtService.ValidateToken(token);
Console.WriteLine($"Valid: {principal?.Identity?.Name ?? "null"}");

// Wait for expiration
Console.WriteLine("Waiting for token to expire...");
await Task.Delay(TimeSpan.FromSeconds(65));

// Validate expired token
var expiredPrincipal = jwtService.ValidateToken(token);
Console.WriteLine($"After expiration: {(expiredPrincipal == null ? "Invalid" : "Valid")}");
```

### Manual Instantiation (Without DI)

```csharp
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;
using System.IdentityModel.Tokens.Jwt;

var options = Options.Create(new MiniJwtOptions
{
    SecretKey = "super-secret-key-at-least-32-bytes-long-hs256",
    Issuer = "ConsoleApp",
    Audience = "ConsoleClient",
    ExpirationMinutes = 1
});

var tokenHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };
var jwtService = new MiniJwtService(
    Options.CreateMonitor(options),
    NullLogger<MiniJwtService>.Instance,
    tokenHandler
);

// Generate token
var token = jwtService.GenerateToken(new { sub = "user1", role = "admin" });
Console.WriteLine($"Token: {token}");

// Validate immediately
var principal = jwtService.ValidateToken(token);
Console.WriteLine($"Valid: {principal?.Identity?.Name ?? "null"}");

// Wait for expiration
Console.WriteLine("Waiting for token to expire...");
await Task.Delay(TimeSpan.FromSeconds(65));

// Validate expired token
var expiredPrincipal = jwtService.ValidateToken(token);
Console.WriteLine($"After expiration: {(expiredPrincipal == null ? "Invalid" : "Valid")}");
```

## Worker Service / Background Service

See [samples/WorkerService](../samples/WorkerService/) for a complete runnable example.

```csharp
using MiniJwt.Core.Services;

public class TokenGeneratorWorker : BackgroundService
{
    private readonly IMiniJwtService _jwtService;
    private readonly ILogger<TokenGeneratorWorker> _logger;

    public TokenGeneratorWorker(
        IMiniJwtService jwtService, 
        ILogger<TokenGeneratorWorker> logger)
    {
        _jwtService = jwtService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var payload = new 
                { 
                    sub = $"worker-{Guid.NewGuid()}", 
                    timestamp = DateTime.UtcNow.ToString("O") 
                };

                var token = _jwtService.GenerateToken(payload);
                
                if (token != null)
                {
                    _logger.LogInformation("Generated token: {Token}", token[..50] + "...");
                    
                    // Validate it
                    var principal = _jwtService.ValidateToken(token);
                    _logger.LogInformation("Token validation: {Result}", 
                        principal != null ? "Success" : "Failed");
                }

                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in token generation worker");
                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }
    }
}
```

## Advanced Scenarios

### Custom Claims with Different Types

```csharp
using MiniJwt.Core.Attributes;

public class ExtendedPayload
{
    [MiniJwtClaim("sub")]
    public string UserId { get; set; }

    [MiniJwtClaim("age")]
    public int Age { get; set; }

    [MiniJwtClaim("premium")]
    public bool IsPremium { get; set; }

    [MiniJwtClaim("balance")]
    public decimal Balance { get; set; }

    [MiniJwtClaim("lastLogin")]
    public DateTime? LastLogin { get; set; }
}

// MiniJwt.Core automatically converts types when deserializing
var payload = new ExtendedPayload
{
    UserId = "user123",
    Age = 30,
    IsPremium = true,
    Balance = 1234.56m,
    LastLogin = DateTime.UtcNow
};

var token = jwtService.GenerateToken(payload);
var deserialized = jwtService.ValidateAndDeserialize<ExtendedPayload>(token);
```

### Middleware for Automatic Token Validation

```csharp
public class JwtValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IMiniJwtService _jwtService;

    public JwtValidationMiddleware(RequestDelegate next, IMiniJwtService jwtService)
    {
        _next = next;
        _jwtService = jwtService;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Request.Headers["Authorization"]
            .FirstOrDefault()?.Replace("Bearer ", "");

        if (!string.IsNullOrEmpty(token))
        {
            var principal = _jwtService.ValidateToken(token);
            if (principal != null)
            {
                context.User = principal;
            }
        }

        await _next(context);
    }
}

// Register in Program.cs
app.UseMiddleware<JwtValidationMiddleware>();
```

### Unit Testing

```csharp
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Extensions;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;
using System.IdentityModel.Tokens.Jwt;
using Xunit;

public class JwtServiceTests
{
    // Option 1: Using AddMiniJwt (Recommended)
    private IMiniJwtService CreateServiceWithDI()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(options =>
        {
            options.SecretKey = "test-secret-key-at-least-32-bytes-long";
            options.Issuer = "TestApp";
            options.Audience = "TestClient";
            options.ExpirationMinutes = 60;
        });

        var serviceProvider = services.BuildServiceProvider();
        return serviceProvider.GetRequiredService<IMiniJwtService>();
    }

    // Option 2: Manual instantiation
    private IMiniJwtService CreateServiceManually()
    {
        var options = Options.Create(new MiniJwtOptions
        {
            SecretKey = "test-secret-key-at-least-32-bytes-long",
            Issuer = "TestApp",
            Audience = "TestClient",
            ExpirationMinutes = 60
        });

        return new MiniJwtService(
            Options.CreateMonitor(options),
            NullLogger<MiniJwtService>.Instance,
            new JwtSecurityTokenHandler { MapInboundClaims = false }
        );
    }

    [Fact]
    public void GenerateToken_ValidPayload_ReturnsToken()
    {
        var service = CreateServiceWithDI();
        var token = service.GenerateToken(new { sub = "test" });
        
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Fact]
    public void ValidateToken_ValidToken_ReturnsPrincipal()
    {
        var service = CreateServiceWithDI();
        var token = service.GenerateToken(new { sub = "test123" });
        
        var principal = service.ValidateToken(token);
        
        Assert.NotNull(principal);
        Assert.Equal("test123", principal.FindFirst("sub")?.Value);
    }
}
```

### Testing with TimeProvider for Deterministic Time

```csharp
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using System.IdentityModel.Tokens.Jwt;
using Xunit;

public class JwtServiceTimeTests
{
    // Simple test helper for IOptionsMonitor
    private class SimpleOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable OnChange(Action<T, string> listener) => new NoOpDisposable();
    }

    private class NoOpDisposable : IDisposable
    {
        public void Dispose() { }
    }

    [Fact]
    public void GenerateToken_WithFakeTimeProvider_UsesProvidedTime()
    {
        // Arrange: Set up a fake time provider at a specific time
        var fakeTimeProvider = new FakeTimeProvider();
        var fixedTime = new DateTimeOffset(2024, 1, 15, 10, 30, 0, TimeSpan.Zero);
        fakeTimeProvider.SetUtcNow(fixedTime);

        var options = new SimpleOptionsMonitor<MiniJwtOptions>(new MiniJwtOptions
        {
            SecretKey = "test-secret-key-at-least-32-bytes-long",
            Issuer = "TestApp",
            Audience = "TestClient",
            ExpirationMinutes = 60
        });

        // Create service with fake time provider
        var service = new MiniJwtService(
            options,
            NullLogger<MiniJwtService>.Instance,
            new JwtSecurityTokenHandler { MapInboundClaims = false },
            fakeTimeProvider
        );

        // Act: Generate a token
        var token = service.GenerateToken(new { sub = "test-user" });

        // Assert: Verify the token uses the fake time
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        
        Assert.Equal(fixedTime.UtcDateTime, jwtToken.ValidFrom);
        Assert.Equal(fixedTime.AddMinutes(60).UtcDateTime, jwtToken.ValidTo);

        // Advance time and generate another token
        fakeTimeProvider.Advance(TimeSpan.FromMinutes(10));
        var token2 = service.GenerateToken(new { sub = "test-user2" });
        
        var jwtToken2 = handler.ReadJwtToken(token2);
        Assert.Equal(fixedTime.AddMinutes(10).UtcDateTime, jwtToken2.ValidFrom);
    }
}
```

## Runnable Sample Applications

We provide complete, runnable sample applications in the repository:

1. **[ConsoleMinimal](../samples/ConsoleMinimal/)** - Basic console app demonstrating token generation and validation
2. **[ASPNetCoreAuth](../samples/ASPNetCoreAuth/)** - Full ASP.NET Core web API with authentication
3. **[WorkerService](../samples/WorkerService/)** - Background service example

### Running the Samples

```bash
# Clone the repository
git clone https://github.com/jeanlrnt/MiniJwt.Core.git
cd MiniJwt.Core

# Run Console sample
cd samples/ConsoleMinimal
dotnet run

# Run ASP.NET Core sample
cd samples/ASPNetCoreAuth
dotnet run
# Then access https://localhost:5001/swagger

# Run Worker Service sample
cd samples/WorkerService
dotnet run
```

## Next Steps

- Review [configuration options](configuration.md)
- Read [security best practices](faq.md)
- Explore the [API documentation](https://www.nuget.org/packages/MiniJwt.Core)

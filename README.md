# MiniJwt.Core

<!-- Continuous Integration (main test/build workflow) -->
[![CI](https://img.shields.io/github/actions/workflow/status/jeanlrnt/MiniJwt.Core/ci.yml?label=CI&style=flat-square&logo=github)](https://github.com/jeanlrnt/MiniJwt.Core/actions)
[![Publish](https://img.shields.io/github/actions/workflow/status/jeanlrnt/MiniJwt.Core/publish.yml?label=publish&style=flat-square&logo=github)](https://github.com/jeanlrnt/MiniJwt.Core/actions/workflows/nuget-publish.yml)
<!-- Latest GitHub release / tag -->
[![Release](https://img.shields.io/github/v/release/jeanlrnt/MiniJwt.Core?label=latest%20release&style=flat-square)](https://github.com/jeanlrnt/MiniJwt.Core/releases)
[![Release](https://img.shields.io/github/v/release/jeanlrnt/MiniJwt.Core?label=pre%20release&style=flat-square)](https://github.com/jeanlrnt/MiniJwt.Core/releases)
<!-- NuGet package version and total downloads -->
[![NuGet](https://img.shields.io/nuget/v/MiniJwt.Core?label=nuget&style=flat-square)](https://www.nuget.org/packages/MiniJwt.Core)
[![NuGet downloads](https://img.shields.io/nuget/dt/MiniJwt.Core?style=flat-square)](https://www.nuget.org/packages/MiniJwt.Core)
[![dotnet](https://img.shields.io/badge/dotnet-8.0-blue?style=flat-square)](https://dotnet.microsoft.com/)
<!-- Repository info: open issues, contributors, license, last commit -->
[![Open issues](https://img.shields.io/github/issues/jeanlrnt/MiniJwt.Core?style=flat-square)](https://github.com/jeanlrnt/MiniJwt.Core/issues)
[![Contributors](https://img.shields.io/github/contributors/jeanlrnt/MiniJwt.Core?style=flat-square)](https://github.com/jeanlrnt/MiniJwt.Core/graphs/contributors)
[![License](https://img.shields.io/github/license/jeanlrnt/MiniJwt.Core?style=flat-square)](https://github.com/jeanlrnt/MiniJwt.Core/blob/main/LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/jeanlrnt/MiniJwt.Core?style=flat-square)](https://github.com/jeanlrnt/MiniJwt.Core/commits)

MiniJwt.Core is a lightweight, minimal JWT library for .NET that provides a simple and efficient way to generate and validate JWT tokens using attributes on object properties to define claims. It's designed to be dependency-injection friendly, multi-target framework compatible, and easy to integrate.

## Documentation

**[Getting Started Guide](docs/getting-started.md)** - Installation and quick start  
**[Configuration Guide](docs/configuration.md)** - Detailed configuration options  
**[Examples](docs/examples.md)** - Code examples and integration patterns  
**[FAQ](docs/faq.md)** - Common questions and security best practices

## Sample Applications

The repository includes three runnable sample applications demonstrating different integration scenarios:

- **[ConsoleMinimal](samples/ConsoleMinimal/)** - Basic console app for token generation and validation
- **[ASPNetCoreAuth](samples/ASPNetCoreAuth/)** - Full ASP.NET Core web API with JWT authentication
- **[WorkerService](samples/WorkerService/)** - Background service example with periodic token generation

## Requirements

- .NET 8+

## Installation

Via the .NET CLI (after the package is published to NuGet):

```bash
dotnet add package MiniJwt.Core
```

## Usage

### 1) Define the options (e.g. `appsettings.json`)

```json
{
  "MiniJwt": {
    "SecretKey": "a-very-long-secret-key-at-least-32-bytes-...",
    "Issuer": "MyApp",
    "Audience": "MyClient",
    "ExpirationMinutes": 60
  }
}
```

### 2) Register in DI (e.g. `Program.cs` for an ASP.NET Core app)

```csharp
using Microsoft.Extensions.DependencyInjection;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<MiniJwtOptions>(builder.Configuration.GetSection("MiniJwt"));
// The service depends on IOptions<MiniJwtOptions> and ILogger<MiniJwtService>
builder.Services.AddSingleton<IMiniJwtService, MiniJwtService>();

var app = builder.Build();
```

Note: `ILogger<MiniJwtService>` is provided automatically by the framework DI. You can choose `AddSingleton`, `AddScoped` or `AddTransient` depending on your needs; the service is stateless after construction and computes the key bytes in the constructor, so `Singleton` is often suitable.

### 3) Define a model with claims

```csharp
using MiniJwt.Core.Attributes;

public class UserJwtPayload
{
    [MiniJwtClaim("id")]
    public int Id { get; set; }

    [MiniJwtClaim("email")]
    public string? Email { get; set; }

    [MiniJwtClaim("name")]
    public string? Name { get; set; }
}
```

### 4) Generate a token

```csharp
// Example inside a controller or service where IMiniJwtService is injected
public class AuthController : ControllerBase
{
    private readonly IMiniJwtService _jwt;

    public AuthController(IMiniJwtService jwt)
    {
        _jwt = jwt;
    }

    public IActionResult Login()
    {
        var payload = new UserJwtPayload { Id = 1, Email = "test@example.com", Name = "Jean" };
        var token = _jwt.GenerateToken(payload);
        if (token == null) return StatusCode(500, "Failed to generate token");
        return Ok(new { token });
    }
}
```

### 5) Validate a token

```csharp
var principal = _jwt.ValidateToken(token);
if (principal == null)
{
    // Invalid token
}
else
{
    // Valid token, access claims via principal.Claims
}
```

### 6) Validate and deserialize to an object

```csharp
var user = _jwt.ValidateAndDeserialize<UserJwtPayload>(token);
if (user == null)
{
    // Invalid token or missing claims
}
else
{
    // user.Id, user.Email, user.Name are populated if present in the token
}
```

## Unit test examples

If you create a service instance manually in a test, provide an `ILogger<MiniJwtService>`. Example using `NullLogger`:

```csharp
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

var options = Options.Create(new MiniJwtOptions
{
    SecretKey = "IntegrationTestSecretKey_LongEnough_For_HS256_0123456789",
    Issuer = "MiniJwt.Tests",
    Audience = "MiniJwt.Tests.Client",
    ExpirationMinutes = 60
});

var svc = new MiniJwtService(options, NullLogger<MiniJwtService>.Instance, new JwtSecurityTokenHandler());
```

### Testing with TimeProvider

For testable time-dependent behavior, the library supports `TimeProvider` (built-in for .NET 8+ or via `Microsoft.Bcl.TimeProvider` for earlier versions). You can inject a `FakeTimeProvider` for deterministic testing:

```csharp
using Microsoft.Extensions.Time.Testing;

var fakeTimeProvider = new FakeTimeProvider();
fakeTimeProvider.SetUtcNow(new DateTimeOffset(2024, 1, 15, 10, 0, 0, TimeSpan.Zero));

var svc = new MiniJwtService(
    options, 
    NullLogger<MiniJwtService>.Instance, 
    new JwtSecurityTokenHandler(),
    fakeTimeProvider
);

// Generate token at the fixed time
var token = svc.GenerateToken(user);

// Advance time for further testing
fakeTimeProvider.Advance(TimeSpan.FromMinutes(5));
```

## Debugging tips

- If `GenerateToken` returns `null`, check the length of the `SecretKey`. It must be at least 32 bytes (for HS256).
- For validation errors, use `ValidateToken` and enable logs to see exceptions captured by the service.
- When publishing via CI (GitHub Actions), use `vMAJOR.MINOR.PATCH` tags to trigger package creation and to set the package version.

## Security

- Never store the secret key in plain text in a public repository.
- Use a secrets manager (Azure Key Vault, GitHub Secrets, etc.) for your keys in CI/CD.

## Quick FAQ

**Q: How do I set the package version when packing?**
A: You can use `/p:PackageVersion=1.2.3` with `dotnet pack` or pack from a project that already has the Version set in the csproj.

**Q: Why does `ValidateAndDeserialize<T>` require `T` to have a parameterless constructor?**
A: The service creates an instance of `T` using the parameterless constructor and then assigns properties from the claims.

## Contributing

Contributions are welcome! Please:
- Follow the existing code style
- Add tests for new features
- Update documentation as needed
- Keep the library minimal and focused

See the [examples documentation](docs/examples.md) for development guidelines.

## Support

If you encounter issues:

1. Check the [FAQ](docs/faq.md)
2. Review the [sample applications](samples/)
3. Search [existing issues](https://github.com/jeanlrnt/MiniJwt.Core/issues)
4. Open a new issue with:
   - .NET version used
   - Minimal reproduction code
   - Logs/stacktraces

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Made with ❤️ by [jeanlrnt](https://github.com/jeanlrnt)
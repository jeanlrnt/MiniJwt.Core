using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;
using System.IdentityModel.Tokens.Jwt;

Console.WriteLine("=== MiniJwt.Core Console Sample ===\n");

// Configure JWT options
var options = new MiniJwtOptions
{
    SecretKey = "super-secret-key-at-least-32-bytes-long-for-hs256",
    Issuer = "ConsoleApp",
    Audience = "ConsoleClient",
    ExpirationMinutes = 1 // 1 minute for demonstration
};

// Create a simple options monitor for console usage
var optionsMonitor = new SimpleOptionsMonitor<MiniJwtOptions>(options);

// Create the JWT service
var tokenHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };
var jwtService = new MiniJwtService(
    optionsMonitor,
    NullLogger<MiniJwtService>.Instance,
    tokenHandler
);

// Define a payload model
var payload = new UserPayload
{
    UserId = "user123",
    Email = "user@example.com",
    Role = "admin"
};

// Generate a token
Console.WriteLine("1. Generating JWT token...");
var token = jwtService.GenerateToken(payload);
if (token == null)
{
    Console.WriteLine("   ❌ Failed to generate token!");
    return;
}
Console.WriteLine($"   ✅ Token generated: {token[..50]}...\n");

// Validate the token immediately
Console.WriteLine("2. Validating token...");
var principal = jwtService.ValidateToken(token);
if (principal != null)
{
    Console.WriteLine("   ✅ Token is valid!");
    Console.WriteLine($"   - Subject: {principal.FindFirst("sub")?.Value}");
    Console.WriteLine($"   - Email: {principal.FindFirst("email")?.Value}");
    Console.WriteLine($"   - Role: {principal.FindFirst("role")?.Value}\n");
}
else
{
    Console.WriteLine("   ❌ Token validation failed!\n");
}

// Validate and deserialize
Console.WriteLine("3. Validating and deserializing token...");
var deserializedUser = jwtService.ValidateAndDeserialize<UserPayload>(token);
if (deserializedUser != null)
{
    Console.WriteLine("   ✅ Token deserialized successfully!");
    Console.WriteLine($"   - UserId: {deserializedUser.UserId}");
    Console.WriteLine($"   - Email: {deserializedUser.Email}");
    Console.WriteLine($"   - Role: {deserializedUser.Role}\n");
}
else
{
    Console.WriteLine("   ❌ Token deserialization failed!\n");
}

// Wait for token to expire
Console.WriteLine("4. Waiting for token to expire (65 seconds)...");
await Task.Delay(TimeSpan.FromSeconds(65));

// Try to validate expired token
Console.WriteLine("\n5. Validating expired token...");
var expiredPrincipal = jwtService.ValidateToken(token);
if (expiredPrincipal == null)
{
    Console.WriteLine("   ✅ Token correctly rejected as expired!\n");
}
else
{
    Console.WriteLine("   ❌ Expired token was incorrectly accepted!\n");
}

Console.WriteLine("=== Sample completed ===");

// Payload model with MiniJwt attributes
public class UserPayload
{
    [MiniJwtClaim("sub")]
    public string UserId { get; set; } = string.Empty;

    [MiniJwtClaim("email")]
    public string Email { get; set; } = string.Empty;

    [MiniJwtClaim("role")]
    public string Role { get; set; } = string.Empty;
}

// Simple IOptionsMonitor implementation for console usage
public class SimpleOptionsMonitor<T> : IOptionsMonitor<T>
{
    private readonly T _currentValue;

    public SimpleOptionsMonitor(T currentValue)
    {
        _currentValue = currentValue;
    }

    public T CurrentValue => _currentValue;

    public T Get(string? name) => _currentValue;

    public IDisposable? OnChange(Action<T, string?> listener) => null;
}

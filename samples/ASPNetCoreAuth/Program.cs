using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Extensions;
using MiniJwt.Core.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add MiniJwt service
builder.Services.AddMiniJwt(options =>
{
    var config = builder.Configuration.GetSection("MiniJwt");
    options.SecretKey = config["SecretKey"] ?? throw new InvalidOperationException("SecretKey not configured");
    options.Issuer = config["Issuer"] ?? "ASPNetCoreAuthSample";
    options.Audience = config["Audience"] ?? "ASPNetCoreAuthClient";
    options.ExpirationMinutes = double.Parse(config["ExpirationMinutes"] ?? "60");
});

// Add JWT Authentication
var jwtConfig = builder.Configuration.GetSection("MiniJwt");
var key = Encoding.UTF8.GetBytes(jwtConfig["SecretKey"] ?? throw new InvalidOperationException("SecretKey not configured"));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = jwtConfig["Issuer"],
            ValidateAudience = true,
            ValidAudience = jwtConfig["Audience"],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Public endpoint - Login
app.MapPost("/auth/login", (LoginRequest request, IMiniJwtService jwtService) =>
{
    // In a real application, validate credentials against a database
    if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new { message = "Username and password are required" });
    }

    // For demo purposes, accept any credentials
    var payload = new UserPayload
    {
        UserId = Guid.NewGuid().ToString(),
        Username = request.Username,
        Email = $"{request.Username}@example.com",
        Role = request.Username == "admin" ? "admin" : "user"
    };

    var token = jwtService.GenerateToken(payload);

    if (token == null)
    {
        return Results.StatusCode(500);
    }

    return Results.Ok(new LoginResponse
    {
        Token = token,
        ExpiresIn = 3600,
        Username = payload.Username,
        Role = payload.Role
    });
})
.WithName("Login")
.WithDescription("Login endpoint - accepts any username/password for demo purposes");

// Public endpoint - Get current time
app.MapGet("/", () => new
{
    message = "MiniJwt.Core ASP.NET Core Auth Sample",
    timestamp = DateTime.UtcNow,
    endpoints = new[]
    {
        "POST /auth/login - Get a JWT token",
        "GET /auth/me - Get current user info (requires auth)",
        "GET /data/public - Public data endpoint",
        "GET /data/protected - Protected data endpoint (requires auth)",
        "GET /data/admin - Admin only endpoint (requires admin role)"
    }
})
.WithName("Root");

// Protected endpoint - Get current user
app.MapGet("/auth/me", (HttpContext context, IMiniJwtService jwtService) =>
{
    var token = context.Request.Headers.Authorization.FirstOrDefault()?.Replace("Bearer ", "");

    if (string.IsNullOrEmpty(token))
    {
        return Results.Unauthorized();
    }

    var user = jwtService.ValidateAndDeserialize<UserPayload>(token);

    if (user == null)
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new
    {
        user.UserId,
        user.Username,
        user.Email,
        user.Role
    });
})
.RequireAuthorization()
.WithName("GetCurrentUser");

// Public endpoint
app.MapGet("/data/public", () => new
{
    message = "This is public data",
    timestamp = DateTime.UtcNow
})
.WithName("PublicData");

// Protected endpoint
app.MapGet("/data/protected", (HttpContext context) => new
{
    message = "This is protected data",
    user = context.User.FindFirst("sub")?.Value,
    timestamp = DateTime.UtcNow
})
.RequireAuthorization()
.WithName("ProtectedData");

// Admin-only endpoint
app.MapGet("/data/admin", (HttpContext context) => new
{
    message = "This is admin-only data",
    admin = context.User.FindFirst("username")?.Value,
    timestamp = DateTime.UtcNow
})
.RequireAuthorization(policy => policy.RequireClaim("role", "admin"))
.WithName("AdminData");

app.Run();

// Request/Response models
public record LoginRequest(string Username, string Password);

public record LoginResponse
{
    public string Token { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}

// User payload with MiniJwt attributes
public class UserPayload
{
    [MiniJwtClaim("sub")]
    public string UserId { get; set; } = string.Empty;

    [MiniJwtClaim("username")]
    public string Username { get; set; } = string.Empty;

    [MiniJwtClaim("email")]
    public string Email { get; set; } = string.Empty;

    [MiniJwtClaim("role")]
    public string Role { get; set; } = string.Empty;
}

# ASPNetCoreAuth Sample

This sample demonstrates how to integrate MiniJwt.Core with ASP.NET Core for JWT-based authentication.

## Features

- Dependency injection registration with `AddMiniJwt()`
- JWT authentication middleware integration
- Login endpoint for token generation
- Protected endpoints requiring authentication
- Role-based authorization
- Public and private API endpoints

## Running the Sample

```bash
cd samples/ASPNetCoreAuth
dotnet run
```

The API will start on `https://localhost:5001` (or the port configured in launchSettings.json).

## API Endpoints

### Public Endpoints

#### GET / - Root endpoint
```bash
curl https://localhost:5001/
```

Returns information about available endpoints.

#### POST /auth/login - Get JWT Token
```bash
curl -X POST https://localhost:5001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "password"}'
```

**Note:** For demo purposes, this endpoint accepts any username/password combination.

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": 3600,
  "username": "testuser",
  "role": "user"
}
```

#### GET /data/public - Public data
```bash
curl https://localhost:5001/data/public
```

### Protected Endpoints (Require Authentication)

#### GET /auth/me - Get current user info
```bash
curl https://localhost:5001/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

#### GET /data/protected - Protected data
```bash
curl https://localhost:5001/data/protected \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

#### GET /data/admin - Admin-only data (requires admin role)
```bash
# Login as admin
curl -X POST https://localhost:5001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Use the admin token
curl https://localhost:5001/data/admin \
  -H "Authorization: Bearer ADMIN_TOKEN_HERE"
```

## Configuration

Configuration is in `appsettings.json`:

```json
{
  "MiniJwt": {
    "SecretKey": "sample-secret-key-at-least-32-bytes-long-for-hs256",
    "Issuer": "ASPNetCoreAuthSample",
    "Audience": "ASPNetCoreAuthClient",
    "ExpirationMinutes": 60
  }
}
```

**Important:** In production, never hardcode the `SecretKey`. Use environment variables, Azure Key Vault, or other secure secret management solutions.

## Key Integration Points

### 1. Service Registration

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

### 2. JWT Authentication Middleware

```csharp
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
```

### 3. Using IMiniJwtService

```csharp
app.MapPost("/auth/login", (LoginRequest request, IMiniJwtService jwtService) =>
{
    var payload = new UserPayload { /* ... */ };
    var token = jwtService.GenerateToken(payload);
    return Results.Ok(new { token });
});
```

### 4. Protecting Endpoints

```csharp
// Requires authentication
app.MapGet("/data/protected", () => { /* ... */ })
    .RequireAuthorization();

// Requires specific role
app.MapGet("/data/admin", () => { /* ... */ })
    .RequireAuthorization(policy => policy.RequireClaim("role", "admin"));
```

## Testing the Flow

1. **Get a token:**
   ```bash
   TOKEN=$(curl -X POST https://localhost:5001/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "testuser", "password": "password"}' \
     -s | jq -r .token)
   ```

2. **Use the token:**
   ```bash
   curl https://localhost:5001/auth/me \
     -H "Authorization: Bearer $TOKEN"
   ```

3. **Try without token (will fail):**
   ```bash
   curl https://localhost:5001/data/protected
   # Returns 401 Unauthorized
   ```

## Production Considerations

1. **Secret Key Management:**
   - Use environment variables or secret managers
   - Rotate keys regularly
   - Never commit secrets to source control

2. **HTTPS:**
   - Always use HTTPS in production
   - The sample uses HTTPS by default

3. **Token Lifetime:**
   - Use shorter lifetimes (15-60 minutes) for access tokens
   - Implement refresh token mechanism for longer sessions

4. **Credential Validation:**
   - This sample accepts any credentials for demo purposes
   - In production, validate against a secure database
   - Hash passwords using bcrypt or similar

5. **Error Handling:**
   - Add proper error handling and logging
   - Don't leak sensitive information in error messages

## Related Documentation

- [Getting Started Guide](../../docs/getting-started.md)
- [Configuration Guide](../../docs/configuration.md)
- [Examples](../../docs/examples.md)
- [Security FAQ](../../docs/faq.md#security-best-practices)

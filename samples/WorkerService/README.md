# WorkerService Sample

This sample demonstrates using MiniJwt.Core in a .NET Worker Service (BackgroundService) for generating and validating JWT tokens in a long-running background process.

## Features

- Integration with .NET Worker Service / BackgroundService
- Dependency injection with `AddMiniJwt()`
- Periodic token generation in a background worker
- Token validation and deserialization
- Logging of token operations

## Use Cases

Worker Services with JWT tokens are useful for:
- Microservices that need to authenticate with other services
- Background jobs that call external APIs requiring JWT authentication
- Token generation for service-to-service communication
- Scheduled tasks that need secure API access

## Running the Sample

```bash
cd samples/WorkerService
dotnet run
```

The worker will:
1. Start and log initialization
2. Generate a JWT token every 10 seconds
3. Validate each generated token
4. Deserialize the token back to the payload object
5. Log all operations

Press `Ctrl+C` to stop the worker.

## Expected Output

```
info: WorkerService.Worker[0]
      Worker started at: 12/18/2024 17:42:10 +00:00
info: WorkerService.Worker[0]
      Generating JWT token #0 for task a1b2c3d4-e5f6...
info: WorkerService.Worker[0]
      Token generated successfully: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ3b3JrZXJ...
info: WorkerService.Worker[0]
      Token validated - WorkerId: worker-MACHINE123, TaskId: a1b2c3d4-e5f6...
info: WorkerService.Worker[0]
      Token deserialized - Counter: 0, Timestamp: 2024-12-18T17:42:10.1234567Z
info: WorkerService.Worker[0]
      Waiting 10 seconds before next token generation...

info: WorkerService.Worker[0]
      Generating JWT token #1 for task b2c3d4e5-f6a7...
...
```

## Configuration

Configuration is in `appsettings.json`:

```json
{
  "MiniJwt": {
    "SecretKey": "worker-secret-key-at-least-32-bytes-long-for-hs256",
    "Issuer": "WorkerServiceSample",
    "Audience": "WorkerServiceClient",
    "ExpirationMinutes": 5
  }
}
```

The token expiration is set to 5 minutes for this sample, but tokens are generated every 10 seconds so you can see fresh tokens being created.

## Key Components

### 1. Service Registration (Program.cs)

```csharp
builder.Services.AddMiniJwt(options =>
{
    var config = builder.Configuration.GetSection("MiniJwt");
    options.SecretKey = config["SecretKey"];
    options.Issuer = config["Issuer"];
    options.Audience = config["Audience"];
    options.ExpirationMinutes = double.Parse(config["ExpirationMinutes"] ?? "5");
});

builder.Services.AddHostedService<Worker>();
```

### 2. Worker Implementation (Worker.cs)

The worker:
- Injects `IMiniJwtService` through constructor
- Runs continuously in the background
- Generates tokens with custom payload every 10 seconds
- Validates and deserializes each token
- Logs all operations

```csharp
public class Worker : BackgroundService
{
    private readonly IMiniJwtService _jwtService;
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var payload = new WorkerPayload { /* ... */ };
            var token = _jwtService.GenerateToken(payload);
            var validated = _jwtService.ValidateToken(token);
            
            await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        }
    }
}
```

### 3. Custom Payload Model

```csharp
public class WorkerPayload
{
    [MiniJwtClaim("worker_id")]
    public string WorkerId { get; set; }
    
    [MiniJwtClaim("task_id")]
    public string TaskId { get; set; }
    
    [MiniJwtClaim("timestamp")]
    public string Timestamp { get; set; }
    
    [MiniJwtClaim("counter")]
    public int Counter { get; set; }
}
```

## Real-World Scenarios

### Scenario 1: API Client Worker

A background worker that periodically calls an external API:

```csharp
protected override async Task ExecuteAsync(CancellationToken stoppingToken)
{
    while (!stoppingToken.IsCancellationRequested)
    {
        // Generate token for authentication
        var token = _jwtService.GenerateToken(new { service = "worker" });
        
        // Call external API with token
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", token);
        
        var response = await client.GetAsync("https://api.example.com/data");
        
        await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
    }
}
```

### Scenario 2: Service-to-Service Authentication

Generate tokens for authenticating with other microservices:

```csharp
public class ServiceAuthenticator
{
    private readonly IMiniJwtService _jwtService;
    
    public async Task<string> GetServiceTokenAsync()
    {
        var payload = new 
        { 
            service = "order-processor",
            permissions = new[] { "read:orders", "write:orders" }
        };
        
        return _jwtService.GenerateToken(payload) 
            ?? throw new InvalidOperationException("Token generation failed");
    }
}
```

### Scenario 3: Scheduled Token Rotation

Automatically rotate tokens before they expire:

```csharp
protected override async Task ExecuteAsync(CancellationToken stoppingToken)
{
    string currentToken = null;
    var tokenLifetime = TimeSpan.FromMinutes(50); // Rotate before 60-min expiry
    
    while (!stoppingToken.IsCancellationRequested)
    {
        currentToken = _jwtService.GenerateToken(new { service = "background" });
        _logger.LogInformation("Token rotated");
        
        // Store token in distributed cache or shared state
        await _cache.SetAsync("service-token", currentToken);
        
        await Task.Delay(tokenLifetime, stoppingToken);
    }
}
```

## Deployment Considerations

### Running as Windows Service

```bash
dotnet publish -c Release -r win-x64
sc create "MyWorkerService" binPath="C:\path\to\WorkerService.exe"
sc start "MyWorkerService"
```

### Running as Linux Systemd Service

Create `/etc/systemd/system/myworker.service`:

```ini
[Unit]
Description=MiniJwt Worker Service
After=network.target

[Service]
Type=notify
WorkingDirectory=/opt/myworker
ExecStart=/opt/myworker/WorkerService
Restart=always
User=myworkeruser

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable myworker
sudo systemctl start myworker
sudo systemctl status myworker
```

### Docker Container

```dockerfile
FROM mcr.microsoft.com/dotnet/runtime:8.0
WORKDIR /app
COPY publish/ .
ENTRYPOINT ["dotnet", "WorkerService.dll"]
```

## Monitoring and Health Checks

Add health checks to monitor the worker:

```csharp
builder.Services.AddHealthChecks()
    .AddCheck<JwtHealthCheck>("jwt-service");

public class JwtHealthCheck : IHealthCheck
{
    private readonly IMiniJwtService _jwtService;
    
    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, 
        CancellationToken cancellationToken = default)
    {
        var token = _jwtService.GenerateToken(new { test = "health" });
        var isHealthy = token != null && _jwtService.ValidateToken(token) != null;
        
        return Task.FromResult(isHealthy 
            ? HealthCheckResult.Healthy("JWT service is working")
            : HealthCheckResult.Unhealthy("JWT service failed"));
    }
}
```

## Related Documentation

- [Getting Started Guide](../../docs/getting-started.md)
- [Configuration Guide](../../docs/configuration.md)
- [Examples](../../docs/examples.md)
- [FAQ](../../docs/faq.md)

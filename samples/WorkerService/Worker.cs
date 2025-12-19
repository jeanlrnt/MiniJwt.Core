using MiniJwt.Core.Attributes;
using MiniJwt.Core.Services;

namespace WorkerService;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IMiniJwtService _jwtService;
    private int _tokenCount = 0;

    public Worker(ILogger<Worker> logger, IMiniJwtService jwtService)
    {
        _logger = logger;
        _jwtService = jwtService;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Worker started at: {time}", DateTimeOffset.Now);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Generate a token with some sample data
                var payload = new WorkerPayload
                {
                    WorkerId = $"worker-{Environment.MachineName}",
                    TaskId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow.ToString("O"),
                    Counter = Interlocked.Increment(ref _tokenCount) - 1
                };

                _logger.LogInformation("Generating JWT token #{Counter} for task {TaskId}...", 
                    payload.Counter, payload.TaskId);

                var token = _jwtService.GenerateToken(payload);

                if (token == null)
                {
                    _logger.LogError("Failed to generate JWT token!");
                }
                else
                {
                    _logger.LogInformation("Token generated successfully: {Token}", 
                        token.Length > 50 ? token[..50] + "..." : token);

                    // Validate the token immediately
                    var principal = _jwtService.ValidateToken(token);
                    
                    if (principal != null)
                    {
                        var workerId = principal.FindFirst("worker_id")?.Value;
                        var taskId = principal.FindFirst("task_id")?.Value;
                        _logger.LogInformation("Token validated - WorkerId: {WorkerId}, TaskId: {TaskId}", 
                            workerId, taskId);

                        // Deserialize back to object
                        var deserialized = _jwtService.ValidateAndDeserialize<WorkerPayload>(token);
                        if (deserialized != null)
                        {
                            _logger.LogInformation("Token deserialized - Counter: {Counter}, Timestamp: {Timestamp}", 
                                deserialized.Counter, deserialized.Timestamp);
                        }
                    }
                    else
                    {
                        _logger.LogWarning("Token validation failed!");
                    }
                }

                // Wait 10 seconds before generating next token
                _logger.LogInformation("Waiting 10 seconds before next token generation...\n");
                await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in worker execution");
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        _logger.LogInformation("Worker stopped at: {time}", DateTimeOffset.Now);
    }
}

// Payload model for worker tokens
public class WorkerPayload
{
    [MiniJwtClaim("worker_id")]
    public string WorkerId { get; set; } = string.Empty;

    [MiniJwtClaim("task_id")]
    public string TaskId { get; set; } = string.Empty;

    [MiniJwtClaim("timestamp")]
    public string Timestamp { get; set; } = string.Empty;

    [MiniJwtClaim("counter")]
    public int Counter { get; set; }
}

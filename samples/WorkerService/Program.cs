using MiniJwt.Core.Extensions;
using WorkerService;

var builder = Host.CreateApplicationBuilder(args);

// Register MiniJwt
builder.Services.AddMiniJwt(options =>
{
    var config = builder.Configuration.GetSection("MiniJwt");
    options.SecretKey = config["SecretKey"] ?? throw new InvalidOperationException("SecretKey not configured");
    options.Issuer = config["Issuer"] ?? "WorkerServiceSample";
    options.Audience = config["Audience"] ?? "WorkerServiceClient";
    options.ExpirationMinutes = double.Parse(config["ExpirationMinutes"] ?? "5");
});

builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();

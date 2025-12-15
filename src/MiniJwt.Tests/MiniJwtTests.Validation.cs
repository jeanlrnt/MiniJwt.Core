using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Extensions;
using Xunit;

namespace MiniJwt.Tests;

public partial class MiniJwtTests
{
    private const string ValidSecretKey = "your-very-secure-secret-key-here-32charsmin!";

    [Fact]
    public async Task ValidateOnStart_WithValidOptions_StartsSuccessfully()
    {
        var builder = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.AddMiniJwt(opts =>
                {
                    opts.SecretKey = ValidSecretKey;
                    opts.Issuer = "TestIssuer";
                    opts.Audience = "TestAudience";
                    opts.ExpirationMinutes = 60;
                });
            });

        
        using var host = builder.Build();
        await host.StartAsync();
        await host.StopAsync();
    }
}
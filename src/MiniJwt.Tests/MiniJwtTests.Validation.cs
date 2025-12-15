using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Extensions;
using Xunit;

namespace MiniJwt.Tests;

public partial class MiniJwtTests
{
    private const string TooShortKey = "too-short-key";
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
    
    [Fact]
    public async Task ValidateOnStart_WithMissingOptions_ShouldThrowOptionsValidationException()
    {
        var builder = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.AddMiniJwt(_ => { });
            });

        await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            using var host = builder.Build();
            await host.StartAsync();
        });
    }

    [Fact]
    public async Task ValidateOnStart_WithInvalidKeySize_ShouldThrowOptionsValidationException()
    {
        var builder = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.AddMiniJwt(opts =>
                {
                    opts.SecretKey = TooShortKey;
                });
            });

        await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            using var host = builder.Build();
            await host.StartAsync();
        });
    }
    
    [Fact]
    public async Task ValidateOnStart_WithInvalidExpiration_ShouldThrowOptionsValidationException()
    {
        var builder = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.AddMiniJwt(opts =>
                {
                    opts.SecretKey = ValidSecretKey;
                    opts.ExpirationMinutes = 0;
                });
            });

        await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            using var host = builder.Build();
            await host.StartAsync();
        });
    }
    
    [Fact]
    public async Task ValidateOnStart_WithNegativeExpiration_ShouldThrowOptionsValidationException()
    {
        var builder = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.AddMiniJwt(opts =>
                {
                    opts.SecretKey = ValidSecretKey;
                    opts.ExpirationMinutes = -10;
                });
            });

        await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            using var host = builder.Build();
            await host.StartAsync();
        });
    }
    
    [Fact]
    public async Task ValidateOnStart_WithWhitespaceIssuer_ShouldThrowOptionsValidationException()
    {
        var builder = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.AddMiniJwt(opts =>
                {
                    opts.SecretKey = ValidSecretKey;
                    opts.Issuer = "   ";
                });
            });

        await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            using var host = builder.Build();
            await host.StartAsync();
        });
    }

    [Fact]
    public async Task ValidateOnStart_WithWhitespaceAudience_ShouldThrowOptionsValidationException()
    {
        var builder = Host.CreateDefaultBuilder()
            .ConfigureServices((_, services) =>
            {
                services.AddMiniJwt(opts =>
                {
                    opts.SecretKey = ValidSecretKey;
                    opts.Audience = "   ";
                });
            });
        await Assert.ThrowsAsync<OptionsValidationException>(async () =>
        {
            using var host = builder.Build();
            await host.StartAsync();
        });
    }
}
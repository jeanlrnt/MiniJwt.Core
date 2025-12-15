using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Extensions;
using MiniJwt.Core.Models;
using Xunit;

namespace MiniJwt.Tests;

public partial class MiniJwtTests
{
    private const string SuperSecretKey = "your-very-secure-secret-key-here";
    private Action<MiniJwtOptions> BasicOptions => options =>
    {
        options.SecretKey = SuperSecretKey;
        options.Issuer = "TestIssuer";
        options.Audience = "TestAudience";
        options.ExpirationMinutes = 60;
    };
    
    [Fact]
    public void ServiceCollectionExtensions_AddMiniJwt()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(BasicOptions);

        var serviceProvider = services.BuildServiceProvider();
        var miniJwtService = serviceProvider.GetService<Core.Services.IMiniJwtService>();

        Assert.NotNull(miniJwtService);
        Assert.IsType<Core.Services.MiniJwtService>(miniJwtService);
    }

    [Fact]
    public void ServiceCollectionExtensions_AddMiniJwt_NullConfigure_ThrowsException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => services.AddMiniJwt(null!));
        Assert.Throws<ArgumentNullException>(() => ServiceCollectionExtensions.AddMiniJwt(services, null!));
    }

    [Fact]
    public void ServiceCollectionExtensions_AddMiniJwt_MultipleCalls()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(options => { options.SecretKey = $"First{SuperSecretKey}"; });
        services.AddMiniJwt(options => { options.SecretKey = $"Second{SuperSecretKey}"; });
        var serviceProvider = services.BuildServiceProvider();
        var miniJwtService = serviceProvider.GetService<Core.Services.IMiniJwtService>();
        Assert.NotNull(miniJwtService);
        var options = serviceProvider.GetService<IOptions<Core.Models.MiniJwtOptions>>();
        Assert.NotNull(options);
        Assert.NotEqual($"First{SuperSecretKey}", options.Value.SecretKey);
        Assert.Equal($"Second{SuperSecretKey}", options.Value.SecretKey);
    }

    [Fact]
    public void ServiceCollectionExtensions_AddMiniJwt_DefaultOptions()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(options =>
        {
            options.SecretKey = SuperSecretKey;
        });
        var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetService<IOptions<Core.Models.MiniJwtOptions>>();
        Assert.NotNull(options);
        Assert.Equal(SuperSecretKey, options.Value.Issuer);
        Assert.Equal(string.Empty, options.Value.SecretKey);
        Assert.Equal(string.Empty, options.Value.Audience);
        Assert.Equal(60, options.Value.ExpirationMinutes);
    }

    [Fact]
    public void ServiceCollectionExtensions_AddMiniJwt_OptionsConfiguration()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(options =>
        {
            options.SecretKey = SuperSecretKey;
            options.Issuer = "TestIssuer";
            options.Audience = "TestAudience";
            options.ExpirationMinutes = 120;
        });
        var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetService<IOptions<Core.Models.MiniJwtOptions>>();
        Assert.NotNull(options);
        Assert.Equal(SuperSecretKey, options.Value.SecretKey);
        Assert.Equal("TestIssuer", options.Value.Issuer);
        Assert.Equal("TestAudience", options.Value.Audience);
        Assert.Equal(120, options.Value.ExpirationMinutes);
    }
    
    [Fact]
    public void ServiceCollectionExtensions_AddMiniJwt_MiniJwtOptionsUsed()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(options =>
        {
            options.SecretKey = SuperSecretKey;
            options.Issuer = "TestIssuer";
            options.Audience = "TestAudience";
            options.ExpirationMinutes = 120;
        });
        var serviceProvider = services.BuildServiceProvider();
        var miniJwtService = serviceProvider.GetService<Core.Services.IMiniJwtService>();
        Assert.NotNull(miniJwtService);

        var token = miniJwtService.GenerateToken(new { });
        Assert.NotNull(token);
        
        var principal = miniJwtService.ValidateToken(token);
        Assert.NotNull(principal);
        
        var claims = principal.Claims.ToList();
        Assert.Contains(claims, c => c is { Type: "iss", Value: "TestIssuer" });
        Assert.Contains(claims, c => c is { Type: "aud", Value: "TestAudience" });
        Assert.Contains(principal.Claims, c => c.Type == "exp"); // Expiration
        Assert.Contains(principal.Claims, c => c.Type == "iat"); // Issued At
        Assert.True(long.Parse(principal.Claims.First(c => c.Type == "exp").Value) - long.Parse(principal.Claims.First(c => c.Type == "iat").Value) <= 120 * 60);
    }
    
    [Fact]
    public void ServiceCollectionExtensions_AddMiniJwt_LoggingServiceRegistered()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(options => { options.SecretKey = SuperSecretKey; });
        var serviceProvider = services.BuildServiceProvider();
        var logger = serviceProvider.GetService<ILogger<Core.Services.MiniJwtService>>();
        Assert.NotNull(logger);
        
        var miniJwtService = serviceProvider.GetService<Core.Services.IMiniJwtService>();
        Assert.NotNull(miniJwtService);
        
        // Ensure that the logger is functional
        logger.LogInformation("Logger is working in MiniJwtService test.");
    }
}
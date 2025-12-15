using System;
using Microsoft.Extensions.DependencyInjection;
using MiniJwt.Core.Extensions;
using Xunit;

namespace MiniJwt.Tests;

public partial class MiniJwtTests
{
    [Fact]
    public void Test_ServiceCollectionExtensions_AddMiniJwt()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(options =>
        {
            options.SecretKey = "TestSecretKey";
        });

        var serviceProvider = services.BuildServiceProvider();
        var miniJwtService = serviceProvider.GetService<Core.Services.IMiniJwtService>();

        Assert.NotNull(miniJwtService);
        Assert.IsType<Core.Services.MiniJwtService>(miniJwtService);
        Assert.NotNull(serviceProvider.GetService<Microsoft.Extensions.Logging.ILogger<Core.Services.MiniJwtService>>());
        Assert.NotNull(serviceProvider.GetService<Microsoft.Extensions.Options.IOptions<Core.Models.MiniJwtOptions>>());
        Assert.Equal("TestSecretKey", serviceProvider.GetService<Microsoft.Extensions.Options.IOptions<Core.Models.MiniJwtOptions>>()!.Value.SecretKey);
    }

    [Fact]
    public void Test_ServiceCollectionExtensions_AddMiniJwt_NullConfigure_ThrowsException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => services.AddMiniJwt(null!));
        Assert.Throws<ArgumentNullException>(() => ServiceCollectionExtensions.AddMiniJwt(services, null!));
    }

    [Fact]
    public void Test_ServiceCollectionExtensions_AddMiniJwt_MultipleCalls()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(options => { options.SecretKey = "FirstSecretKey"; });
        services.AddMiniJwt(options => { options.SecretKey = "SecondSecretKey"; });
        var serviceProvider = services.BuildServiceProvider();
        var miniJwtService = serviceProvider.GetService<Core.Services.IMiniJwtService>();
        Assert.NotNull(miniJwtService);
        var options = serviceProvider.GetService<Microsoft.Extensions.Options.IOptions<Core.Models.MiniJwtOptions>>();
        Assert.NotNull(options);
        Assert.NotEqual("FirstSecretKey", options.Value.SecretKey);
        Assert.Equal("SecondSecretKey", options.Value.SecretKey);
    }

    [Fact]
    public void Test_ServiceCollectionExtensions_AddMiniJwt_DefaultOptions()
    {
        var services = new ServiceCollection();
        services.AddMiniJwt(_ => { });
        var serviceProvider = services.BuildServiceProvider();
        var options = serviceProvider.GetService<Microsoft.Extensions.Options.IOptions<Core.Models.MiniJwtOptions>>();
        Assert.NotNull(options);
        Assert.Equal(string.Empty, options.Value.SecretKey);
        Assert.Equal(string.Empty, options.Value.Issuer);
        Assert.Equal(string.Empty, options.Value.Audience);
        Assert.Equal(60, options.Value.ExpirationMinutes);
    }
}
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
    }

    [Fact]
    public void Test_ServiceCollectionExtensions_AddMiniJwt_NullConfigure_ThrowsException()
    {
        var services = new ServiceCollection();
        Assert.Throws<ArgumentNullException>(() => services.AddMiniJwt(null!));
    }
}
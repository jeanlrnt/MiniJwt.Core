using Microsoft.Extensions.DependencyInjection;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;

namespace MiniJwt.Core.Extensions;


public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMiniJwt(this IServiceCollection services, Action<MiniJwtOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = services.AddOptions<MiniJwtOptions>().Configure(configure);

        builder.ValidateOnStart();

        services.AddLogging();
        services.Configure(configure);
        services.AddSingleton<IMiniJwtService, MiniJwtService>();

        return services;
    }
}
 using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;
using MiniJwt.Core.Validators;

namespace MiniJwt.Core.Extensions;


public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddMiniJwt(this IServiceCollection services, Action<MiniJwtOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        var builder = services.AddOptions<MiniJwtOptions>().Configure(configure);

        builder.Services.AddSingleton<IValidateOptions<MiniJwtOptions>, MiniJwtOptionsValidator>();
        builder.ValidateOnStart();

        services.AddLogging();
        services.Configure(configure);
        services.AddSingleton<IMiniJwtService, MiniJwtService>();

        return services;
    }
}
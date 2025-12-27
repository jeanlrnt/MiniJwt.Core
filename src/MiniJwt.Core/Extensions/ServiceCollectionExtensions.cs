using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
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
        
        // Register IMiniJwtService with a factory to create a local JwtSecurityTokenHandler
        // This avoids polluting the consumer's DI container
        services.AddSingleton<IMiniJwtService>(sp => 
        {
            var optionsMonitor = sp.GetRequiredService<IOptionsMonitor<MiniJwtOptions>>();
            var logger = sp.GetRequiredService<ILogger<MiniJwtService>>();
            
            // Resolve TimeProvider (available in .NET 8+ DI) or fallback to System
            var timeProvider = sp.GetService<TimeProvider>() ?? TimeProvider.System;

            // Create a local instance specifically for MiniJwt to avoid global side effects
            var tokenHandler = new JwtSecurityTokenHandler { MapInboundClaims = false };

            return new MiniJwtService(optionsMonitor, logger, tokenHandler, timeProvider);
        });

        return services;
    }
}
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using MiniJwt.Core.Services;

namespace MiniJwt.Core.Extensions;

public static class MiniJwtExtensions
{
    public static IServiceCollection AddMiniJwt(this IServiceCollection services, Action<MiniJwtOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddSingleton<IMiniJwtService, MiniJwtService>();
        return services;
    }

    public static IApplicationBuilder UseMiniJwt(this IApplicationBuilder app)
    {
        return app.Use(async (context, next) =>
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (!string.IsNullOrEmpty(token))
            {
                try
                {
                    // Résolution du service depuis le Scope de la requête
                    var jwtService = context.RequestServices.GetRequiredService<IMiniJwtService>();
                    
                    var principal = jwtService.ValidateToken(token);
                    if (principal is not null) 
                        context.User = principal;
                }
                catch
                {
                    // Token invalide, on continue sans authentifier
                }
            }

            await next();
        });
    }
}
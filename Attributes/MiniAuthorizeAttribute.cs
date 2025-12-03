using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace MiniJwt.Core.Attributes;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public class MiniAuthorizeAttribute : Attribute, IEndpointFilter
{
    public string? RequiredRole { get; set; }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var user = context.HttpContext.User;

        // 1. Vérifie si l'utilisateur est authentifié (rempli par le Middleware)
        if (user?.Identity?.IsAuthenticated != true)
        {
            return Results.Unauthorized();
        }

        // 2. Vérifie le rôle si nécessaire
        if (!string.IsNullOrEmpty(RequiredRole))
        {
            // Note: Le claim de rôle standard est souvent mappé, on vérifie ici simplement
            var hasRole = user.Claims.Any(c => c.Type == "role" && c.Value == RequiredRole) 
                       || user.IsInRole(RequiredRole);

            if (!hasRole)
            {
                return Results.Forbid();
            }
        }

        return await next(context);
    }
}
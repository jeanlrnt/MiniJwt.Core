using System.Security.Claims;

namespace MiniJwt.Core.Services;

public interface IMiniJwtService
{
     string? GenerateToken<T>(T payload);
    ClaimsPrincipal? ValidateToken(string token);
    T? ValidateAndDeserialize<T>(string token) where T : new();
}
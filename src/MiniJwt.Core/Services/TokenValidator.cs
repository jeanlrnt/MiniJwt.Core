using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MiniJwt.Core.Attributes;

namespace MiniJwt.Core.Services;

public static class TokenValidator
{
    public static ClaimsPrincipal GetPrincipal(string token, string secretKey, string issuer, string audience)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        tokenHandler.MapInboundClaims = false;
        var key = Encoding.ASCII.GetBytes(secretKey);

        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero 
        };

        return tokenHandler.ValidateToken(token, parameters, out _);
    }

    public static T ValidateAndDeserialize<T>(string token, string secretKey, string issuer, string audience) where T : new()
    {
        var principal = GetPrincipal(token, secretKey, issuer, audience);
        var result = new T();

        foreach (var prop in typeof(T).GetProperties())
        {
            var attr = prop.GetCustomAttribute<JwtClaimAttribute>();
            if (attr != null)
            {
                var claim = principal.Claims.FirstOrDefault(c => c.Type == attr.ClaimType);
                if (claim != null)
                {
                    // Conversion basique (String -> PropType)
                    // Pour un vrai package, il faudrait gérer int, bool, guid, etc. plus robustement
                    if (prop.PropertyType == typeof(string))
                        prop.SetValue(result, claim.Value);
                    else if (prop.PropertyType == typeof(int))
                        prop.SetValue(result, int.Parse(claim.Value));
                     // Ajouter d'autres types au besoin
                }
            }
        }
        return result;
    }
}
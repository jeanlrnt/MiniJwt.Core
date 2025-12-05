using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Globalization;
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
                    try
                    {
                        var targetType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;
                        if (targetType == typeof(string))
                        {
                            prop.SetValue(result, claim.Value);
                        }
                        else if (targetType == typeof(int))
                        {
                            if (int.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out var v))
                                prop.SetValue(result, v);
                        }
                        else if (targetType == typeof(long))
                        {
                            if (long.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out var v))
                                prop.SetValue(result, v);
                        }
                        else if (targetType == typeof(double))
                        {
                            if (double.TryParse(claim.Value, NumberStyles.Any, CultureInfo.InvariantCulture, out var v))
                                prop.SetValue(result, v);
                        }
                        else if (targetType == typeof(bool))
                        {
                            if (bool.TryParse(claim.Value, out var v))
                                prop.SetValue(result, v);
                        }
                        else
                        {
                            // Attempt a general conversion as fallback
                            var converted = Convert.ChangeType(claim.Value, targetType, CultureInfo.InvariantCulture);
                            prop.SetValue(result, converted);
                        }
                    }
                    catch
                    {
                        // Ignore conversion errors and continue
                    }
                }
            }
        }
        return result;
    }
}
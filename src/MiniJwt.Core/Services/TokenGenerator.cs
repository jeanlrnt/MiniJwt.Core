using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Globalization;
using Microsoft.IdentityModel.Tokens;
using MiniJwt.Core.Attributes;

namespace MiniJwt.Core.Services;

public static class TokenGenerator
{
    public static string? GenerateToken<T>(T payload, string secretKey, string issuer, string audience, TimeSpan lifetime)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(secretKey);
        
        var claims = new List<Claim>();

        // Réflexion : Récupérer les propriétés marquées par [JwtClaim]
        foreach (var prop in typeof(T).GetProperties())
        {
            var attr = prop.GetCustomAttribute<JwtClaimAttribute>();
            if (attr != null)
            {
                var rawValue = prop.GetValue(payload);
                if (rawValue != null)
                {
                    string value;
                    if (rawValue is IFormattable formattable)
                        value = formattable.ToString(null, CultureInfo.InvariantCulture);
                    else
                        value = rawValue.ToString()!;

                    if (!string.IsNullOrEmpty(value))
                    {
                        claims.Add(new Claim(attr.ClaimType, value));
                    }
                }
            }
        }

        // Ajout des claims standards
        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.Add(lifetime),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        try
        {
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        catch (ArgumentOutOfRangeException) // clé trop courte pour HS256
        {
            // Conformément à la stratégie choisie, ne pas lever : retourner null pour indiquer l'échec
            return null;
        }
        catch (ArgumentException)
        {
            // Même stratégie : retourner null si la création échoue
            return null;
        }
        catch (Exception)
        {
            // Pour être sûr que la méthode ne lève pas en contexte de tests, on capture et retourne null
            return null;
        }
    }
}
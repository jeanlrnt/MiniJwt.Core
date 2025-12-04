using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using MiniJwt.Core.Attributes;

namespace MiniJwt.Core.Services;

public static class TokenGenerator
{
    public static string GenerateToken<T>(T payload, string secretKey, string issuer, string audience, TimeSpan lifetime)
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
                var value = prop.GetValue(payload)?.ToString();
                if (!string.IsNullOrEmpty(value))
                {
                    claims.Add(new Claim(attr.ClaimType, value));
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

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}
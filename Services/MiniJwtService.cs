using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MiniJwt.Core.Attributes;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;

namespace MiniJwt.Core.Services;

public class MiniJwtService : IMiniJwtService
{
    private readonly MiniJwtOptions _options;
    private readonly byte[] _keyBytes;

    public MiniJwtService(IOptions<MiniJwtOptions> options)
    {
        _options = options.Value;
        // On prépare la clé une seule fois pour optimiser
        _keyBytes = Encoding.ASCII.GetBytes(_options.SecretKey);
    }

    public string GenerateToken<T>(T payload)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var claims = new List<Claim>();

        // Logique de Réflexion (identique à avant)
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

        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_options.ExpirationMinutes),
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_keyBytes), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public ClaimsPrincipal ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        
        var parameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(_keyBytes),
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        return tokenHandler.ValidateToken(token, parameters, out _);
    }

    public T? ValidateAndDeserialize<T>(string token) where T : new()
    {
        // On réutilise la méthode ValidateToken interne
        var principal = ValidateToken(token);
        var result = new T();

        foreach (var prop in typeof(T).GetProperties())
        {
            var attr = prop.GetCustomAttribute<JwtClaimAttribute>();
            if (attr != null)
            {
                var claim = principal.Claims.FirstOrDefault(c => c.Type == attr.ClaimType);
                if (claim != null)
                {
                    // Gestion simple des types (à étendre selon besoins)
                    if (prop.PropertyType == typeof(string))
                        prop.SetValue(result, claim.Value);
                    else if (prop.PropertyType == typeof(int) && int.TryParse(claim.Value, out int i))
                        prop.SetValue(result, i);
                }
            }
        }
        return result;
    }
}
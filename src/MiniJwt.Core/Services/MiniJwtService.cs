using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MiniJwt.Core.Attributes;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Globalization;
using MiniJwt.Core.Models;

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

    public string? GenerateToken<T>(T payload)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var claims = new List<Claim>();
        
        foreach (var prop in typeof(T).GetProperties())
        {
            var attr = prop.GetCustomAttribute<JwtClaimAttribute>();
            if (attr is null) continue;
            var rawValue = prop.GetValue(payload);
            if (rawValue is null) continue;
            TrySetProperty(rawValue, prop, attr.ClaimType);
        }

        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
        
        if (_keyBytes.Length < 32)
        {
            return null; // La clé trop courte pour HS256, on ne peut pas générer de token valide
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_options.ExpirationMinutes),
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(_keyBytes), SecurityAlgorithms.HmacSha256Signature)
        };

        try
        {
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        catch
        {
            return null; // En cas d'erreur lors de la création du token, on retourne null
        }
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler
        {
            MapInboundClaims = false
        };

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

        try
        {
            var principal = tokenHandler.ValidateToken(token, parameters, out _);
            return principal;
        }
        catch (Exception)
        {
            return null; // En cas d'erreur de validation, on retourne null
        }
    }

    public T? ValidateAndDeserialize<T>(string token) where T : new()
    {
        var principal = ValidateToken(token);
        if (principal == null)
        {
            return default;
        }

        var result = new T();

        foreach (var prop in typeof(T).GetProperties())
        {
            var attr = prop.GetCustomAttribute<JwtClaimAttribute>();
            if (attr == null) continue;
            var claim = principal.Claims.FirstOrDefault(c => c.Type == attr.ClaimType);
            if (claim == null) continue;
            TrySetProperty(result, prop, claim.Value);
        }
        return result;
    }

    private void TrySetProperty<T>(T obj, PropertyInfo prop, string value)
    {
        var targetType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;
        var typeCode = Type.GetTypeCode(targetType);
        
        switch (typeCode)
        {
            case TypeCode.Empty or TypeCode.Object or TypeCode.DBNull:
                // types not handled: ne rien faire
                return;
            case TypeCode.String:
                prop.SetValue(obj, value);
                return;
            case TypeCode.Char:
                prop.SetValue(obj, char.Parse(value));
                return;
            default:
            {
                try
                {
                    var converted = Convert.ChangeType(value, targetType, CultureInfo.InvariantCulture);
                    prop.SetValue(obj, converted);
                }
                catch
                {
                    // En cas d'erreur de conversion, on ignore et ne set pas la propriété
                }
                break;
            }
        }
    }
}

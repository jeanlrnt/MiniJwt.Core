using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MiniJwt.Core.Attributes;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Globalization;
using Microsoft.Extensions.Logging;
using MiniJwt.Core.Models;

namespace MiniJwt.Core.Services;

public class MiniJwtService : IMiniJwtService, IDisposable
{
    private readonly ILogger _logger;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly IDisposable? _optionsChangeRegistration;
    private readonly object _sync = new object();

    // volatile-like references for atomic reads/writes under lock
    private SigningCredentials? _signingCredentials;
    private TokenValidationParameters? _validationParameters;
    private MiniJwtOptions _options;

    private const int MinimumKeyLengthBytes = 32; // 256 bits for HS256

    public MiniJwtService(IOptionsMonitor<MiniJwtOptions> optionsMonitor, ILogger<MiniJwtService> logger, JwtSecurityTokenHandler tokenHandler)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _tokenHandler = tokenHandler ?? throw new ArgumentNullException(nameof(tokenHandler));
        _options = optionsMonitor.CurrentValue ?? throw new ArgumentNullException(nameof(optionsMonitor));
        
        RefreshFromOptions(_options);

        _optionsChangeRegistration = optionsMonitor.OnChange(opts =>
        {
            try
            {
                lock (_sync)
                {
                    _options = opts;
                    RefreshFromOptions(opts);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to refresh MiniJwtService from changed options.");
            }
        });
    }
    
    private void RefreshFromOptions(MiniJwtOptions opts)
    {
        if (opts is null) throw new ArgumentNullException(nameof(opts));

        var keyBytes = Encoding.UTF8.GetBytes(opts.SecretKey ?? string.Empty);

        if (keyBytes.Length < MinimumKeyLengthBytes)
        {
            _logger.LogWarning("Secret key too short for HS256. It must be at least {MinBytes} bytes.", MinimumKeyLengthBytes);
        }

        var symmetricKey = new SymmetricSecurityKey(keyBytes);

        // créer de nouveaux objets thread-safe et réutilisables
        _signingCredentials = new SigningCredentials(symmetricKey, SecurityAlgorithms.HmacSha256);
        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = symmetricKey,
            ValidateIssuer = !string.IsNullOrWhiteSpace(opts.Issuer),
            ValidIssuer = opts.Issuer,
            ValidateAudience = !string.IsNullOrWhiteSpace(opts.Audience),
            ValidAudience = opts.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        };
    }

    /// <inheritdoc/>
    public string? GenerateToken<T>(T payload)
    {
        SigningCredentials? signingCredentials;
        MiniJwtOptions currentOptions;
        lock (_sync)
        {
            signingCredentials = _signingCredentials;
            currentOptions = _options;
        }

        if (signingCredentials is null)
        {
            _logger.LogWarning("Signing credentials not initialized.");
            return null;
        }
        
        var props = typeof(T).GetProperties(BindingFlags.Instance | BindingFlags.Public);
        var claims = new List<Claim>(props.Length + 1);
        
        foreach (var prop in props)
        {
            var attr = prop.GetCustomAttribute<MiniJwtClaimAttribute>();
            if (attr is null) continue;
            var raw = prop.GetValue(payload);
            if (raw is null) continue;
            claims.Add(new Claim(attr.ClaimType, raw.ToString() ?? string.Empty));
        }

        claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

        var now = DateTime.UtcNow;
        var expires = now.AddMinutes(currentOptions.ExpirationMinutes);

        var jwt = new JwtSecurityToken(
            issuer: currentOptions.Issuer,
            audience: currentOptions.Audience,
            claims: claims,
            notBefore: now,
            expires: expires,
            signingCredentials: signingCredentials
        );

        try
        {
            return _tokenHandler.WriteToken(jwt);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error generating JWT token.");
            return null;
        }
    }

    /// <inheritdoc/>
    public ClaimsPrincipal? ValidateToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;

        TokenValidationParameters? parameters;
        lock (_sync)
        {
            parameters = _validationParameters;
        }

        if (parameters is null)
        {
            _logger.LogWarning("Token validation parameters not initialized.");
            return null;
        }

        try
        {
            var principal = _tokenHandler.ValidateToken(token, parameters, out _);
            foreach (var identity in principal.Identities)
            {
                var claims = identity.Claims.ToList();
                foreach (var claim in claims)
                {
                    // Some claims may have additional properties set (e.g., when deserialized from certain token sources or libraries).
                    // In such cases, we replace the claim with a new one using the first property value as the claim type and the original claim value.
                    // This normalization ensures that claims are accessible by their expected type in downstream code, avoiding issues with non-standard claim representations.
                    if (claim.Properties.Any())
                    {
                        var newClaim = new Claim(claim.Properties.First().Value, claim.Value);
                        identity.RemoveClaim(claim);
                        identity.AddClaim(newClaim);
                    }
                }
            }
            return principal;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "JWT token validation failed.");
            return null;
        }
    }

    /// <inheritdoc/>
    public T? ValidateAndDeserialize<T>(string token) where T : new()
    {
        var principal = ValidateToken(token);
        if (principal == null) return default;

        var result = new T();
        var props = typeof(T).GetProperties(BindingFlags.Instance | BindingFlags.Public);

        foreach (var prop in props)
        {
            var attr = prop.GetCustomAttribute<MiniJwtClaimAttribute>();
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
                return;
            case TypeCode.String:
                prop.SetValue(obj, value);
                return;
            case TypeCode.Char:
                try
                {
                    prop.SetValue(obj, char.Parse(value));
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to convert claim value '{Value}' to type {Type} for property {Property}. Skipping assignment.", value, targetType.Name, prop.Name);
                }
                return;
            default:
                try
                {
                    var converted = Convert.ChangeType(value, targetType, CultureInfo.InvariantCulture);
                    prop.SetValue(obj, converted);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to convert claim value '{Value}' to type {Type} for property {Property}. Skipping assignment.", value, targetType.Name, prop.Name);
                }
                break;
        }
    }

    public void Dispose()
    {
        _optionsChangeRegistration?.Dispose();
    }
}

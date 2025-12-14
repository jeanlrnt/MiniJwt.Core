using System.Security.Claims;

namespace MiniJwt.Core.Services;

/// <summary>
/// Service interface for generating and validating JWT tokens.
/// </summary>
public interface IMiniJwtService
{
    /// <summary>
    /// Generates a JWT token with the given payload.
    /// </summary>
    /// <param name="payload">
    ///  The payload object containing properties decorated with MiniJwtClaimAttribute.
    /// </param>
    /// <typeparam name="T">
    ///  The type of the payload.
    /// </typeparam>
    /// <returns></returns>
     string? GenerateToken<T>(T payload);
    
    /// <summary>
    /// Validates the given JWT token and returns the claims principal if valid.
    /// </summary>
    /// <param name="token">
    ///  The JWT token to validate.
    /// </param>
    /// <returns>
    ///  The claims principal if the token is valid; otherwise, null.
    /// </returns>
    ClaimsPrincipal? ValidateToken(string token);
    
    /// <summary>
    /// Validates the given JWT token and deserializes its claims into an object of type T.
    /// </summary>
    /// <param name="token">
    ///  The JWT token to validate and deserialize.
    /// </param>
    /// <typeparam name="T">
    ///  The type to deserialize the claims into. Must have a parameterless constructor.
    /// </typeparam>
    T? ValidateAndDeserialize<T>(string token) where T : new();
}
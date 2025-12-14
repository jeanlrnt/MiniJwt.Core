namespace MiniJwt.Core.Models;

/// <summary>
/// Configuration options for MiniJwt.
/// </summary>
public class MiniJwtOptions
{
    /// <summary>
    /// Gets or sets the secret key used for signing JWT tokens.
    /// </summary>
    /// <default>This is an empty string by default and should be set to a secure value.</default>
    /// <example>
    /// <code language="csharp">
    /// var options = new MiniJwtOptions
    /// {
    ///     SecretKey = "your-very-secure-secret-key-here"
    /// };
    /// </code>
    /// </example>
    public string SecretKey { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the issuer of the JWT tokens.
    /// </summary>
    /// <default>This is an empty string by default and should be set to your application's issuer.</default>
    public string Issuer { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the audience for the JWT tokens.
    /// </summary>
    /// <default>This is an empty string by default and should be set to your application's audience.</default>
    public string Audience { get; set; } = string.Empty;
    /// <summary>
    /// Gets or sets the expiration time in minutes for the JWT tokens.
    /// </summary>
    /// <default>60 minutes by default.</default>
    /// <example>
    /// <code language="csharp">
    /// var options = new MiniJwtOptions
    /// {
    ///     ExpirationMinutes = 0.5 // Tokens will expire in 30 seconds
    /// };
    /// </code>
    /// </example>
    public double ExpirationMinutes { get; set; } = 60;
}
namespace MiniJwt.Core.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class MiniJwtClaimAttribute : Attribute
{
    /// <summary>
    /// Gets the type of the claim associated with the property.
    /// </summary>
    /// <example>
    /// <code>
    /// public class UserPayload
    /// {
    ///     [MiniJwtClaim("sub")]
    ///     public string Subject { get; set; }
    /// }
    /// </code>
    /// </example>
    public string ClaimType { get; }
    
    public MiniJwtClaimAttribute(string claimType)
    {
        ClaimType = claimType;
    }
}
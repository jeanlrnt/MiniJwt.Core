namespace MiniJwt.Core.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class JwtClaimAttribute(string claimType) : Attribute
{
    public string ClaimType { get; } = claimType;
}
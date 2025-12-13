namespace MiniJwt.Core.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class MiniJwtClaimAttribute(string claimType) : Attribute
{
    public string ClaimType { get; } = claimType;
}
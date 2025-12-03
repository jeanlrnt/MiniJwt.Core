namespace MiniJwt.Core.Attributes;

[AttributeUsage(AttributeTargets.Property)]
public class JwtClaimAttribute : Attribute
{
    public string ClaimType { get; }

    public JwtClaimAttribute(string claimType)
    {
        ClaimType = claimType;
    }
}
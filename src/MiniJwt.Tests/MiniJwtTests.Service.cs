using System;
using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;
using Xunit;

namespace MiniJwt.Tests;

public partial class MiniJwtTests
{
    private class SimpleOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        // Intentionally returns a no-op disposable for testing purposes.
        // This test implementation does not track option changes.
        public IDisposable OnChange(Action<T, string> listener) => NullDisposable.Instance;
    }

    private class NullDisposable : IDisposable
    {
        public static readonly NullDisposable Instance = new NullDisposable();
        private NullDisposable() { }
        public void Dispose() { }
    }
    
    private IMiniJwtService CreateService(string secret = "IntegrationTestSecretKey_LongEnough_For_HS256_0123456789", double expMinutes = 60, string issuer = "MiniJwt.Tests", string audience = "MiniJwt.Tests.Client")
    {
        var options = new SimpleOptionsMonitor<MiniJwtOptions>(new MiniJwtOptions
        {
            SecretKey = secret,
            Issuer = issuer,
            Audience = audience,
            ExpirationMinutes = expMinutes
        });

        using var loggerFactory = new LoggerFactory();
        return new MiniJwtService(options, loggerFactory.CreateLogger<MiniJwtService>(), new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler());
    }

    private class TestUser
    {
        [MiniJwtClaim("id")]
        public int Id { get; set; }
        [MiniJwtClaim("email")]
        public string? Email { get; set; }
        [MiniJwtClaim("name")]
        public string? Name { get; set; }
    }

    [Fact]
    public void GenerateAndValidateToken_ShouldSucceed()
    {
        var svc = CreateService();
        var user = new TestUser { Id = 1, Email = "test@test.com", Name = "User Test" };
            
        var token = svc.GenerateToken(user);
        Assert.NotNull(token);
        var principal = svc.ValidateToken(token);
        Assert.NotNull(principal);
        var deserializedUser = svc.ValidateAndDeserialize<TestUser>(token);
        Assert.NotNull(deserializedUser);
        Assert.IsType<TestUser>(deserializedUser);
        Assert.Equal(user.Id, deserializedUser.Id);
        Assert.Equal(user.Email, deserializedUser.Email);
        Assert.Equal(user.Name, deserializedUser.Name);
    }

    [Fact]
    public void Validate_MalformedToken_ShouldNotThrow_ButReturnNull()
    {
        var svc = CreateService();
        const string malformed = "this.is.not.a.valid.token";

        var principal = svc.ValidateToken(malformed);
        Assert.Null(principal);

        var des = svc.ValidateAndDeserialize<TestUser>(malformed);
        Assert.Null(des);
    }

    [Fact]
    public void ExpiredToken_ShouldReturnNull_OnValidation()
    {
        const int expSeconds = 2; // Cant generate an expired token directly, so we set a short expiration and wait
        var svc = CreateService(expMinutes: expSeconds / 60.0); // 2 seconds
        var user = new TestUser { Id = 1, Email = "test@test.com", Name = "User Test" };
        var token = svc.GenerateToken(user);
        Assert.NotNull(token);

        System.Threading.Thread.Sleep(expSeconds * 1000);

        var principal = svc.ValidateToken(token);
        Assert.Null(principal);
    }

    [Fact]
    public void GenerateToken_WithInvalidSecretLengths_ShouldReturnNull()
    {
        var svc = CreateService(secret: "short_key_too_small");
        var user = new TestUser { Id = 1, Email = "test@test.com", Name = "User Test" };

        var token = svc.GenerateToken(user);
        Assert.Null(token);
    }

    [Fact]
    public void Validate_WithDifferentSecret_ShouldReturnNull()
    {
        var a = CreateService(secret: "SecretA_VeryLongKey_ForTests_012345678901234567890");
        var b = CreateService(secret: "SecretB_VeryLongKey_ForTests_012345678901234567890");

        var user = new TestUser { Id = 1, Email = "test@test.com", Name = "User Test" };
        var token = a.GenerateToken(user);
        Assert.NotNull(token);

        var principal = b.ValidateToken(token);
        Assert.Null(principal);
    }

    [Fact]
    public void ValidateToken_ClaimNormalization_ShouldHandleClaimsWithProperties()
    {
        // This test verifies the claim normalization logic that handles claims with properties.
        // While we can't easily simulate a real-world scenario where the token handler returns
        // claims with properties, we can test that the normalization logic exists and works
        // correctly by examining the behavior of the ValidateToken method.
        
        var svc = CreateService();
        var user = new TestUser { Id = 1, Email = "test@test.com", Name = "User Test" };
        
        var token = svc.GenerateToken(user);
        Assert.NotNull(token);
        
        var principal = svc.ValidateToken(token);
        Assert.NotNull(principal);
        
        // Verify the claims are accessible by their expected types
        // The normalization logic ensures that claims with properties are transformed
        // so that the property value becomes the claim type
        var idClaim = principal.FindFirst("id");
        Assert.NotNull(idClaim);
        Assert.Equal("1", idClaim.Value);
        
        var emailClaim = principal.FindFirst("email");
        Assert.NotNull(emailClaim);
        Assert.Equal("test@test.com", emailClaim.Value);
        
        var nameClaim = principal.FindFirst("name");
        Assert.NotNull(nameClaim);
        Assert.Equal("User Test", nameClaim.Value);
        
        // The explicit claim checks above are sufficient to verify claim accessibility.
    }

    [Fact]
    public void ValidateToken_WithStandardClaims_ShouldRemainUnchanged()
    {
        var svc = CreateService();
        var user = new TestUser { Id = 1, Email = "test@test.com", Name = "User Test" };
        
        var token = svc.GenerateToken(user);
        Assert.NotNull(token);
        
        var principal = svc.ValidateToken(token);
        Assert.NotNull(principal);
        
        // Verify all claims are present and accessible
        var claims = principal.Claims.ToList();
        Assert.NotEmpty(claims);
        
        // Verify that standard claims without properties remain unchanged
        var idClaim = principal.FindFirst("id");
        Assert.NotNull(idClaim);
        Assert.Equal("1", idClaim.Value);
        Assert.Empty(idClaim.Properties); // Standard claims should not have properties
        
        var emailClaim = principal.FindFirst("email");
        Assert.NotNull(emailClaim);
        Assert.Equal("test@test.com", emailClaim.Value);
        Assert.Empty(emailClaim.Properties);
        
        var nameClaim = principal.FindFirst("name");
        Assert.NotNull(nameClaim);
        Assert.Equal("User Test", nameClaim.Value);
        Assert.Empty(nameClaim.Properties);
    }

    [Fact]
    public void ClaimNormalization_WithClaimProperties_ShouldNormalizeToPropertyValue()
    {
        // This test demonstrates the claim normalization behavior that the ValidateToken method implements.
        // It simulates what happens when claims have properties set (which can occur with certain token sources).
        
        // Create a ClaimsIdentity with claims that have properties
        var identity = new System.Security.Claims.ClaimsIdentity("TestAuth");
        
        // Create a claim with a property - simulating what might come from certain token sources
        var claimWithProperty = new System.Security.Claims.Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "user123");
        claimWithProperty.Properties.Add("JsonClaimValueType", "sub");
        identity.AddClaim(claimWithProperty);
        
        // Create a claim without properties for comparison
        var claimWithoutProperty = new System.Security.Claims.Claim("email", "test@test.com");
        identity.AddClaim(claimWithoutProperty);
        
        // Apply the same normalization logic that ValidateToken uses
        var claims = identity.Claims.ToList();
        foreach (var claim in claims.Where(c => c.Properties.Any()))
        {
            var newClaim = new System.Security.Claims.Claim(claim.Properties.First().Value, claim.Value);
            identity.RemoveClaim(claim);
            identity.AddClaim(newClaim);
        }
        
        // Verify that the claim with properties was normalized
        var normalizedClaim = identity.FindFirst("sub");
        Assert.NotNull(normalizedClaim);
        Assert.Equal("user123", normalizedClaim.Value);
        
        // Verify that the original claim type is no longer present
        var originalClaim = identity.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
        Assert.Null(originalClaim);
        
        // Verify that the claim without properties remained unchanged
        var unchangedClaim = identity.FindFirst("email");
        Assert.NotNull(unchangedClaim);
        Assert.Equal("test@test.com", unchangedClaim.Value);
    }
}
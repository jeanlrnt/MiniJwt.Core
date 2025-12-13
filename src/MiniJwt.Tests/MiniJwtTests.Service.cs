using Microsoft.Extensions.Options;
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;
using Xunit;

namespace MiniJwt.Tests;

public partial class MiniJwtTests
{
    private static MiniJwtService CreateService(string secret = "IntegrationTestSecretKey_LongEnough_For_HS256_0123456789", double expMinutes = 60, string issuer = "MiniJwt.Tests", string audience = "MiniJwt.Tests.Client")
    {
        var options = Options.Create(new MiniJwtOptions
        {
            SecretKey = secret,
            Issuer = issuer,
            Audience = audience,
            ExpirationMinutes = expMinutes
        });

        return new MiniJwtService(options);
    }

    private class TestUser
    {
        [JwtClaim("id")]
        public int Id { get; set; }
        [JwtClaim("email")]
        public string? Email { get; set; }
        [JwtClaim("name")]
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
        const int expSeconds = 2;
        var svc = CreateService(expMinutes: expSeconds / 60.0); // 5 seconds
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
}
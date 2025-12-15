using System;
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
}
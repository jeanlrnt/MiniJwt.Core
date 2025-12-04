using System;
using Microsoft.Extensions.Options;
using MiniJwt.Core;
using MiniJwt.Core.Services;
using MiniJwt.Core.Attributes;
using Xunit;

namespace MiniJwt.Tests;

public class JwtServiceTests
{
    private readonly MiniJwtService _service;

    public JwtServiceTests()
    {
        var options = Options.Create(new MiniJwtOptions
        {
            SecretKey = "UnitTestSecretKey012345678901234567890123",
            Issuer = "MiniJwt.Tests",
            Audience = "MiniJwt.Tests.Client",
            ExpirationMinutes = 60
        });

        _service = new MiniJwtService(options);
    }

    public class TestUser
    {
        [JwtClaim("sub")]
        public int Id { get; set; }

        [JwtClaim("email")]
        public string? Email { get; set; }

        [JwtClaim("name")]
        public string? Name { get; set; }
    }

    [Fact]
    public void GenerateToken_ShouldContainExpectedClaims()
    {
        var user = new TestUser { Id = 42, Email = "test@example.com", Name = "Test" };
        var token = _service.GenerateToken(user);

        var principal = _service.ValidateToken(token);

        Assert.NotNull(principal);
        Assert.Equal("test@example.com", principal.FindFirst("email")?.Value);
        Assert.Equal("Test", principal.FindFirst("name")?.Value);
        Assert.Equal("42", principal.FindFirst("sub")?.Value);
    }

    [Fact]
    public void ValidateAndDeserialize_ShouldReturnOriginalPayload()
    {
        var user = new TestUser { Id = 7, Email = "u@e.com", Name = "U" };
        var token = _service.GenerateToken(user);

        var deserialized = _service.ValidateAndDeserialize<TestUser>(token);

        Assert.NotNull(deserialized);
        Assert.Equal(user.Id, deserialized?.Id);
        Assert.Equal(user.Email, deserialized?.Email);
        Assert.Equal(user.Name, deserialized?.Name);
    }
}


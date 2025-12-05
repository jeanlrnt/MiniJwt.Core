using System;
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Services;
using Xunit;

namespace MiniJwt.Tests.Unit;

public class TokenGeneratorTests
{
    public class User
    {
        [JwtClaim("sub")] public int Id { get; set; }
        [JwtClaim("name")] public string? Name { get; set; }
    }

    [Fact]
    public void GenerateToken_ShouldContainClaims_FromAttribute()
    {
        var token = TokenGenerator.GenerateToken(new User { Id = 11, Name = "T" }, "UnitTests_SecretKey_LongEnough_For_HS256_0123456789", "iss", "aud", TimeSpan.FromMinutes(10));
        Assert.False(string.IsNullOrEmpty(token));

        var principal = TokenValidator.GetPrincipal(token, "UnitTests_SecretKey_LongEnough_For_HS256_0123456789", "iss", "aud");
        Assert.NotNull(principal);
        Assert.Equal("T", principal.FindFirst("name")?.Value);
        Assert.Equal("11", principal.FindFirst("sub")?.Value);
    }

    [Fact]
    public void Generate_WithShortKey_ShouldThrowOrBeHandled_ButNotCrash()
    {
        var ex = Record.Exception(() => TokenGenerator.GenerateToken(new User { Id = 1 }, "short", "iss", "aud", TimeSpan.FromMinutes(1)));
        Assert.Null(ex);
    }
}

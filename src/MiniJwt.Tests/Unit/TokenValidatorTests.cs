using System;
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Services;
using Xunit;

namespace MiniJwt.Tests.Unit;

public class TokenValidatorTests
{
    public class Payload
    {
        [JwtClaim("sub")] public int Id { get; set; }
        [JwtClaim("flag")] public bool Flag { get; set; }
        [JwtClaim("dbl")] public double Dbl { get; set; }
    }

    [Fact]
    public void ValidateAndDeserialize_ShouldDeserialize_TypesCorrectly()
    {
        var secret = "UnitTests_SecretKey_LongEnough_For_HS256_0123456789";
        var token = TokenGenerator.GenerateToken(new Payload { Id = 2, Flag = true, Dbl = 2.5 }, secret, "iss", "aud", TimeSpan.FromMinutes(5));

        var res = TokenValidator.ValidateAndDeserialize<Payload>(token, secret, "iss", "aud");
        Assert.Equal(2, res.Id);
        Assert.True(res.Flag);
        Assert.Equal(2.5, res.Dbl, 3);
    }

    [Fact]
    public void GetPrincipal_WithInvalidToken_ShouldThrow()
    {
        var secret = "UnitTests_SecretKey_LongEnough_For_HS256_0123456789";
        var ex = Record.Exception(() => TokenValidator.GetPrincipal("not.a.jwt", secret, "iss", "aud"));
        Assert.NotNull(ex);
    }
}

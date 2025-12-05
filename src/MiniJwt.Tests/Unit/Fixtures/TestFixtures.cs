using Microsoft.Extensions.Options;
using MiniJwt.Core;
using MiniJwt.Core.Services;

namespace MiniJwt.Tests.Unit.Fixtures;

public static class TestFixtures
{
    public static MiniJwtService CreateService(string secret = "UnitTests_SecretKey_LongEnough_For_HS256_0123456789", int expMinutes = 60, string issuer = "MiniJwt.UnitTests", string audience = "MiniJwt.UnitTests.Client")
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
}

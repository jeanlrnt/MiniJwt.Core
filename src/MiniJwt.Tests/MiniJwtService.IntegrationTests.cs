using Microsoft.Extensions.Options;
using MiniJwt.Core;
using MiniJwt.Core.Services;
using Xunit;

namespace MiniJwt.Tests
{
    public class MiniJwtServiceIntegrationTests
    {
        private static MiniJwtService CreateService(string secret = "IntegrationTestSecretKey_LongEnough_For_HS256_0123456789", int expMinutes = 60, string issuer = "MiniJwt.IntegrationTests", string audience = "MiniJwt.IntegrationTests.Client")
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

        public class TestUser
        {
            // propriétés utilisées pour la désérialisation des tests d'intégration
            public int Id { get; set; }
            public string? Email { get; set; }
            public string? Name { get; set; }
        }

        [Fact]
        public void Validate_MalformedToken_ShouldNotThrow_ButReturnNull()
        {
            var svc = CreateService();
            var malformed = "this.is.not.a.valid.token";

            var principal = svc.ValidateToken(malformed);
            Assert.Null(principal);

            var des = svc.ValidateAndDeserialize<TestUser>(malformed);
            Assert.Null(des);

            // Usage factice des propriétés pour satisfaire les analyseurs (aucun impact runtime)
            var t = new TestUser();
            t.Id = 0; t.Email = null; t.Name = null;
            _ = t.Id; _ = t.Email; _ = t.Name;
        }

        [Fact]
        public void ExpiredToken_ShouldReturnNull_OnValidation()
        {
            var svc = CreateService(expMinutes: 0);
            var user = new TestUser { Id = 1, Email = "e@e.com", Name = "E" };
            var token = svc.GenerateToken(user);

            System.Threading.Thread.Sleep(1200);

            var principal = svc.ValidateToken(token);
            Assert.Null(principal);

            // usage factice
            _ = user.Id; _ = user.Email; _ = user.Name;
        }

        [Fact]
        public void GenerateToken_WithInvalidSecretLengths_ShouldBeHandledByService()
        {
            // Si la clé est trop courte, la création de token doit être robuste (le service retente avec une expiration min)
            var svc = CreateService(secret: "short_key_too_small");
            var user = new TestUser { Id = 2, Email = "a@b.com", Name = "A" };

            var ex = Record.Exception(() => svc.GenerateToken(user));
            Assert.Null(ex);

            _ = user.Id; _ = user.Email; _ = user.Name;
        }

        [Fact]
        public void Validate_WithDifferentSecret_ShouldReturnNull()
        {
            var a = CreateService(secret: "SecretA_VeryLongKey_ForTests_012345678901234567890");
            var b = CreateService(secret: "SecretB_VeryLongKey_ForTests_012345678901234567890");

            var user = new TestUser { Id = 2, Email = "a@b.com", Name = "A" };
            var token = a.GenerateToken(user);

            var principal = b.ValidateToken(token);
            Assert.Null(principal);

            _ = user.Id; _ = user.Email; _ = user.Name;
        }
    }
}

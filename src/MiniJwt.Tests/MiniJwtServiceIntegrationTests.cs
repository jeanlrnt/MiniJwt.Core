using Microsoft.Extensions.Options;
using MiniJwt.Core;
using MiniJwt.Core.Services;
using MiniJwt.Core.Attributes;
using Xunit;

namespace MiniJwt.Tests
{
    public class MiniJwtServiceIntegrationTests
    {
        private static MiniJwtService CreateService(int expirationMinutes = 60)
        {
            var options = Options.Create(new MiniJwtOptions
            {
                SecretKey = "IntegrationTestSecretKey012345678901234567890",
                Issuer = "MiniJwt.Tests.Integration",
                Audience = "MiniJwt.Tests.Client",
                ExpirationMinutes = expirationMinutes
            });

            return new MiniJwtService(options);
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
        public void GenerateAndValidate_ShouldNotThrow_AndContainExpectedClaims()
        {
            var service = CreateService();
            var user = new TestUser { Id = 42, Email = "int@test.com", Name = "Integration" };

            var genEx = Record.Exception(() => { var _ = service.GenerateToken(user); });
            Assert.Null(genEx);

            var token = service.GenerateToken(user);
            var valEx = Record.Exception(() => { var _ = service.ValidateToken(token); });
            Assert.Null(valEx);

            var principal = service.ValidateToken(token);
            Assert.NotNull(principal);
            Assert.Equal("int@test.com", principal.FindFirst("email")?.Value);
            Assert.Equal("Integration", principal.FindFirst("name")?.Value);
            Assert.Equal("42", principal.FindFirst("sub")?.Value);
        }

        [Fact]
        public void ValidateAndDeserialize_ShouldNotThrow_AndReturnOriginalPayload()
        {
            var service = CreateService();
            var user = new TestUser { Id = 7, Email = "u@e.com", Name = "U" };

            var token = service.GenerateToken(user);

            var ex = Record.Exception(() =>
            {
                var deserialized = service.ValidateAndDeserialize<TestUser>(token);
                Assert.NotNull(deserialized);
                Assert.Equal(user.Id, deserialized?.Id);
                Assert.Equal(user.Email, deserialized?.Email);
                Assert.Equal(user.Name, deserialized?.Name);
            });

            Assert.Null(ex);
        }

        [Fact]
        public void Validate_MalformedToken_ShouldNotThrow()
        {
            var service = CreateService();
            var malformed = "this.is.not.a.valid.token";

            var ex = Record.Exception(() =>
            {
                var principal = service.ValidateToken(malformed);
                // Accept either null or a principal but ensure no exception
            });

            Assert.Null(ex);
        }

        [Fact]
        public void ExpiredToken_ShouldNotThrow_OnValidation()
        {
            var service = CreateService(expirationMinutes: -1); // token already expired
            var user = new TestUser { Id = 1, Email = "e@e.com", Name = "E" };

            var token = service.GenerateToken(user);

            var ex = Record.Exception(() =>
            {
                var principal = service.ValidateToken(token);
                // Ensure validation does not throw even if token is expired
            });

            Assert.Null(ex);
        }

        [Fact]
        public void ValidateAndDeserialize_InvalidToken_ShouldNotThrow()
        {
            var service = CreateService();
            var invalid = "invalid.token.value";

            var ex = Record.Exception(() =>
            {
                var deserialized = service.ValidateAndDeserialize<TestUser>(invalid);
                // Accept null result but ensure no exception
            });

            Assert.Null(ex);
        }
    }
}

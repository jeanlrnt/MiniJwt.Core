using Microsoft.Extensions.Options;
using MiniJwt.Core;
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Services;
using Xunit;

namespace MiniJwt.Tests
{
    public class MiniJwtServiceUnitTests
    {
        private static MiniJwtService CreateService(string secret = "UnitTests_SecretKey_LongEnough_For_HS256_0123456789", int expMinutes = 60, string issuer = "MiniJwt.UnitTests", string audience = "MiniJwt.UnitTests.Client")
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
            [JwtClaim("sub")] public int Id { get; set; }
            [JwtClaim("email")] public string? Email { get; set; }
            [JwtClaim("name")] public string? Name { get; set; }
        }

        public class MixedTypesUser
        {
            [JwtClaim("sub")] public int Id { get; set; }
            [JwtClaim("longval")] public long? LongValue { get; set; }
            [JwtClaim("dbl")] public double Dbl { get; set; }
            [JwtClaim("flag")] public bool Flag { get; set; }
            [JwtClaim("maybe")] public int? MaybeNull { get; set; }
            [JwtClaim("name")] public string? Name { get; set; }
        }

        [Fact]
        public void GenerateToken_ShouldContainExpectedClaims()
        {
            var svc = CreateService();
            var user = new TestUser { Id = 42, Email = "test@example.com", Name = "Test" };
            var token = svc.GenerateToken(user);

            var principal = svc.ValidateToken(token);

            Assert.NotNull(principal);
            Assert.Equal("test@example.com", principal.FindFirst("email")?.Value);
            Assert.Equal("Test", principal.FindFirst("name")?.Value);
            Assert.Equal("42", principal.FindFirst("sub")?.Value);
        }

        [Fact]
        public void ValidateAndDeserialize_ShouldReturnOriginalPayload()
        {
            var svc = CreateService();
            var user = new TestUser { Id = 7, Email = "u@e.com", Name = "U" };
            var token = svc.GenerateToken(user);

            var deserialized = svc.ValidateAndDeserialize<TestUser>(token);

            Assert.NotNull(deserialized);
            Assert.Equal(user.Id, deserialized.Id);
            Assert.Equal(user.Email, deserialized.Email);
            Assert.Equal(user.Name, deserialized.Name);
        }

        [Fact]
        public void Generate_WithMissingClaims_ShouldStillProduceTokenWithJti()
        {
            var svc = CreateService();
            var user = new MixedTypesUser { Id = 1, Name = null };

            var token = svc.GenerateToken(user);
            Assert.NotNull(token);

            var principal = svc.ValidateToken(token);
            Assert.NotNull(principal);

            Assert.NotNull(principal.FindFirst("jti")?.Value);
        }

        [Fact]
        public void TypeConversions_ShouldDeserializeNumericAndBoolValues()
        {
            var svc = CreateService();
            var user = new MixedTypesUser { Id = 5, LongValue = 1234567890123, Dbl = 3.14, Flag = true, MaybeNull = null, Name = "X" };

            var token = svc.GenerateToken(user);
            var des = svc.ValidateAndDeserialize<MixedTypesUser>(token);

            Assert.NotNull(des);
            Assert.Equal(user.Id, des.Id);
            Assert.Equal(user.LongValue, des.LongValue);
            Assert.Equal(user.Dbl, des.Dbl);
            Assert.Equal(user.Flag, des.Flag);
            Assert.Equal(user.MaybeNull, des?.MaybeNull);
            Assert.Equal(user.Name, des?.Name);
        }

        [Fact]
        public void Validate_WithDifferentSecret_ShouldReturnNull()
        {
            var a = CreateService(secret: "SecretA_VeryLongKey_ForTests_012345678901234567890");
            var b = CreateService(secret: "SecretB_VeryLongKey_ForTests_012345678901234567890");

            var user = new MixedTypesUser { Id = 2, Name = "A" };
            var token = a.GenerateToken(user);

            var principal = b.ValidateToken(token);
            Assert.Null(principal);

            var des = b.ValidateAndDeserialize<MixedTypesUser>(token);
            Assert.Null(des);
        }

        [Fact]
        public void ExpiredToken_ShouldReturnNull_OnValidate()
        {
            var svc = CreateService(expMinutes: 0);
            var user = new MixedTypesUser { Id = 3, Name = "E" };
            var token = svc.GenerateToken(user);

            System.Threading.Thread.Sleep(1200);

            var principal = svc.ValidateToken(token);
            Assert.Null(principal);
        }

        [Fact]
        public void MalformedToken_ShouldReturnNull_NotThrow()
        {
            var svc = CreateService();
            var malformed = "not.a.jwt";
            var principal = svc.ValidateToken(malformed);
            Assert.Null(principal);

            var des = svc.ValidateAndDeserialize<MixedTypesUser>(malformed);
            Assert.Null(des);
        }

        [Fact]
        public void Jti_ShouldBeUniqueAcrossTokens()
        {
            var svc = CreateService();
            var t1 = svc.GenerateToken(new MixedTypesUser { Id = 9 });
            var t2 = svc.GenerateToken(new MixedTypesUser { Id = 10 });

            var p1 = svc.ValidateToken(t1);
            var p2 = svc.ValidateToken(t2);

            Assert.NotNull(p1); Assert.NotNull(p2);
            var j1 = p1!.FindFirst("jti")?.Value;
            var j2 = p2!.FindFirst("jti")?.Value;
            Assert.False(string.IsNullOrEmpty(j1));
            Assert.False(string.IsNullOrEmpty(j2));
            Assert.NotEqual(j1, j2);
        }
    }
}


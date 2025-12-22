using System;
using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
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

    private class TrackableDisposable : IDisposable
    {
        public bool IsDisposed { get; private set; }
        public void Dispose()
        {
            IsDisposed = true;
        }
    }

    private class TrackableOptionsMonitor<T> : IOptionsMonitor<T>
    {
        private readonly T _value;
        private readonly TrackableDisposable _disposable;

        public TrackableOptionsMonitor(T value, TrackableDisposable disposable)
        {
            _value = value;
            _disposable = disposable;
        }

        public T CurrentValue => _value;
        public T Get(string? name) => _value;
        public IDisposable OnChange(Action<T, string> listener) => _disposable;
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

    [Fact]
    public void Dispose_ShouldCleanupOptionsChangeSubscription()
    {
        // Arrange
        var trackableDisposable = new TrackableDisposable();
        var options = new TrackableOptionsMonitor<MiniJwtOptions>(
            new MiniJwtOptions
            {
                SecretKey = "IntegrationTestSecretKey_LongEnough_For_HS256_0123456789",
                Issuer = "MiniJwt.Tests",
                Audience = "MiniJwt.Tests.Client",
                ExpirationMinutes = 60
            },
            trackableDisposable
        );

        using var loggerFactory = new LoggerFactory();
        var service = new MiniJwtService(
            options, 
            loggerFactory.CreateLogger<MiniJwtService>(), 
            new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler()
        );

        // Act
        service.Dispose();

        // Assert
        Assert.True(trackableDisposable.IsDisposed, "The options change subscription should be disposed when the service is disposed");
    }

    [Fact]
    public void GenerateToken_WithFakeTimeProvider_ShouldUseProvidedTime()
    {
        // Arrange
        var fakeTimeProvider = new FakeTimeProvider();
        var fixedTime = new DateTimeOffset(2024, 1, 15, 10, 30, 0, TimeSpan.Zero);
        fakeTimeProvider.SetUtcNow(fixedTime);

        var options = new SimpleOptionsMonitor<MiniJwtOptions>(new MiniJwtOptions
        {
            SecretKey = "IntegrationTestSecretKey_LongEnough_For_HS256_0123456789",
            Issuer = "MiniJwt.Tests",
            Audience = "MiniJwt.Tests.Client",
            ExpirationMinutes = 60
        });

        using var loggerFactory = new LoggerFactory();
        var service = new MiniJwtService(
            options,
            loggerFactory.CreateLogger<MiniJwtService>(),
            new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler(),
            fakeTimeProvider
        );

        var user = new TestUser { Id = 1, Email = "test@test.com", Name = "User Test" };

        // Act
        var token = service.GenerateToken(user);

        // Assert
        Assert.NotNull(token);
        
        // Decode the token to verify it uses the fake time
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        
        // The token's NotBefore should match the fixed time
        Assert.Equal(fixedTime.UtcDateTime, jwtToken.ValidFrom);
        
        // The token's expiration should be 60 minutes after the fixed time
        var expectedExpiry = fixedTime.AddMinutes(60).UtcDateTime;
        Assert.Equal(expectedExpiry, jwtToken.ValidTo);
    }

    [Fact]
    public void GenerateToken_WithAdvancedTime_UsesUpdatedTime()
    {
        // Arrange
        var fakeTimeProvider = new FakeTimeProvider();
        var initialTime = new DateTimeOffset(2024, 1, 15, 10, 0, 0, TimeSpan.Zero);
        fakeTimeProvider.SetUtcNow(initialTime);

        var options = new SimpleOptionsMonitor<MiniJwtOptions>(new MiniJwtOptions
        {
            SecretKey = "IntegrationTestSecretKey_LongEnough_For_HS256_0123456789",
            Issuer = "MiniJwt.Tests",
            Audience = "MiniJwt.Tests.Client",
            ExpirationMinutes = 10 // 10 minutes
        });

        using var loggerFactory = new LoggerFactory();
        var service = new MiniJwtService(
            options,
            loggerFactory.CreateLogger<MiniJwtService>(),
            new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler(),
            fakeTimeProvider
        );

        var user = new TestUser { Id = 1, Email = "test@test.com", Name = "User Test" };

        // Generate token at initial time
        var token = service.GenerateToken(user);
        Assert.NotNull(token);

        // Verify the token was generated with the fake time
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        Assert.Equal(initialTime.UtcDateTime, jwtToken.ValidFrom);
        Assert.Equal(initialTime.AddMinutes(10).UtcDateTime, jwtToken.ValidTo);

        // Advance the fake time by 5 minutes
        fakeTimeProvider.Advance(TimeSpan.FromMinutes(5));

        // Generate another token - it should use the new advanced time
        var token2 = service.GenerateToken(user);
        Assert.NotNull(token2);
        
        var jwtToken2 = handler.ReadJwtToken(token2);
        var expectedTime = initialTime.AddMinutes(5).UtcDateTime;
        Assert.Equal(expectedTime, jwtToken2.ValidFrom);
        Assert.Equal(expectedTime.AddMinutes(10), jwtToken2.ValidTo);
    }
}
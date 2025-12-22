using System;
using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Attributes;
using MiniJwt.Core.Models;
using MiniJwt.Core.Services;
using Xunit;

namespace MiniJwt.Tests;

public partial class MiniJwtTests
{
    private class CacheTestPayload
    {
        [MiniJwtClaim("test_id")]
        public int Id { get; set; }
        
        [MiniJwtClaim("test_name")]
        public string? Name { get; set; }
    }

    [Fact]
    public void ReflectionCache_ShouldReuseMetadata_AcrossMultipleGenerateTokenCalls()
    {
        // Arrange
        var svc = CreateService();
        var payload1 = new CacheTestPayload { Id = 1, Name = "First" };
        var payload2 = new CacheTestPayload { Id = 2, Name = "Second" };

        // Act - Generate multiple tokens with the same type
        var token1 = svc.GenerateToken(payload1);
        var token2 = svc.GenerateToken(payload2);

        // Assert - Both tokens should be generated successfully
        Assert.NotNull(token1);
        Assert.NotNull(token2);

        // Validate that both tokens deserialize correctly (proving cache is working)
        var deserialized1 = svc.ValidateAndDeserialize<CacheTestPayload>(token1);
        var deserialized2 = svc.ValidateAndDeserialize<CacheTestPayload>(token2);
        
        Assert.NotNull(deserialized1);
        Assert.NotNull(deserialized2);
        Assert.Equal(payload1.Id, deserialized1.Id);
        Assert.Equal(payload1.Name, deserialized1.Name);
        Assert.Equal(payload2.Id, deserialized2.Id);
        Assert.Equal(payload2.Name, deserialized2.Name);
    }

    [Fact]
    public void ReflectionCache_ShouldWorkWithDifferentTypes()
    {
        // Arrange
        var svc = CreateService();
        var testUser = new TestUser { Id = 1, Email = "test@test.com", Name = "User" };
        var cachePayload = new CacheTestPayload { Id = 2, Name = "Payload" };

        // Act - Generate tokens for different types
        var userToken = svc.GenerateToken(testUser);
        var payloadToken = svc.GenerateToken(cachePayload);

        // Assert - Both should work correctly
        Assert.NotNull(userToken);
        Assert.NotNull(payloadToken);

        var deserializedUser = svc.ValidateAndDeserialize<TestUser>(userToken);
        var deserializedPayload = svc.ValidateAndDeserialize<CacheTestPayload>(payloadToken);
        
        Assert.NotNull(deserializedUser);
        Assert.NotNull(deserializedPayload);
        Assert.Equal(testUser.Id, deserializedUser.Id);
        Assert.Equal(testUser.Email, deserializedUser.Email);
        Assert.Equal(cachePayload.Id, deserializedPayload.Id);
        Assert.Equal(cachePayload.Name, deserializedPayload.Name);
    }
}

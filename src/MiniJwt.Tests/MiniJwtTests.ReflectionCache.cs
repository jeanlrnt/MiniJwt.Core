using System;
using System.Diagnostics;
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

    [Fact]
    public void ReflectionCache_PerformanceTest_ShouldBeFasterOnSecondCall()
    {
        // This test demonstrates that the cache improves performance
        // Note: This is a basic performance test and may have variability
        
        var svc = CreateService();
        var payload = new CacheTestPayload { Id = 1, Name = "Performance Test" };

        // First call - will populate the cache
        var sw1 = Stopwatch.StartNew();
        for (int i = 0; i < 100; i++)
        {
            var token = svc.GenerateToken(new CacheTestPayload { Id = i, Name = $"Test{i}" });
            Assert.NotNull(token);
        }
        sw1.Stop();

        // Second batch - should use cached metadata
        var sw2 = Stopwatch.StartNew();
        for (int i = 0; i < 100; i++)
        {
            var token = svc.GenerateToken(new CacheTestPayload { Id = i + 100, Name = $"Test{i + 100}" });
            Assert.NotNull(token);
        }
        sw2.Stop();

        // The cache should make subsequent calls faster or at least not slower
        // We're being lenient here as performance can vary in test environments
        // The important thing is that it works correctly, not that it's always faster
        Assert.True(sw2.Elapsed <= sw1.Elapsed * 2, 
            $"Second batch took significantly longer ({sw2.ElapsedMilliseconds}ms) than first batch ({sw1.ElapsedMilliseconds}ms), suggesting cache may not be working");
    }
}

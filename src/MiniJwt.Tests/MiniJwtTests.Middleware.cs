using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using MiniJwt.Core.Extensions;
using MiniJwt.Core.Models;
using Xunit;

namespace MiniJwt.Tests;

public partial class MiniJwtTests
{
    [Fact]
    public async Task UseMiniJwt_ShouldAuthenticateRequest_WhenValidTokenProvided()
    {
        var options = new MiniJwtOptions
        {
            SecretKey = "IntegrationTestSecretKey_LongEnough_For_HS256_0123456789",
            Issuer = "iss",
            Audience = "aud",
            ExpirationMinutes = 60
        };

        var builder = new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddMiniJwt(o =>
                {
                    o.SecretKey = options.SecretKey;
                    o.Issuer = options.Issuer;
                    o.Audience = options.Audience;
                    o.ExpirationMinutes = options.ExpirationMinutes;
                });
                services.AddRouting();
            })
            .Configure(app =>
            {
                app.UseMiniJwt();
                app.UseRouting();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/who", async context =>
                    {
                        var id = context.User.FindFirst("sub")?.Value ?? "-";
                        await context.Response.WriteAsync(id);
                    });
                });
            });

        using var server = new TestServer(builder);
        var client = server.CreateClient();
        var svc = CreateService(options.SecretKey, options.ExpirationMinutes, options.Issuer, options.Audience);

        var token = svc.GenerateToken(new TestUser()
        {
            Id = 1,
            Email = "test@test.com",
            Name = "Test User"
        });
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var res = await client.GetAsync("/who");
        res.EnsureSuccessStatusCode();
        var body = await res.Content.ReadAsStringAsync();
        Assert.Equal("1", body);
    }
}

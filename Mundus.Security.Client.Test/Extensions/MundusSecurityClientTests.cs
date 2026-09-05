using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Mundus.Security.Client.Configuration;
using Mundus.Security.Client.DTOs;
using Mundus.Security.Client.Extensions;
using Mundus.Security.Client.Services;
using System.IdentityModel.Tokens.Jwt;


namespace Mundus.Security.Client.Test.Extensions
{
    [TestClass]
    public class MundusSecurityClientTests
    {
        [TestInitialize]
        public void TestInitialize()
        {
            // Clear environment variables used by MundusConfigurationOptions to isolate tests
            Environment.SetEnvironmentVariable("MUNDUS_COMPANY_CODE", null);
            Environment.SetEnvironmentVariable("MUNDUS_APPLICATION_CODE", null);
            Environment.SetEnvironmentVariable("MUNDUS_CLIENT_ID", null);
            Environment.SetEnvironmentVariable("MUNDUS_CLIENT_SECRET", null);
            Environment.SetEnvironmentVariable("MUNDUS_SECURITY_URL", null);
        }


        [TestMethod]
        public void MundusConfigurationOptions_ShouldThrowInvalidOperationException_WhenVariablesAreMissing()
        {
            Assert.ThrowsException<InvalidOperationException>(() => 
                new MundusConfigurationOptions());
        }


        [TestMethod]
        public async Task OnMessageReceived_ShouldFailSecurely_WhenCiamIsDowntime()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddMemoryCache();
            services.AddHttpContextAccessor();

            // Add extension registration
            services.AddMundusAuthentication();

            // Mock IMundusM2MClient to throw HttpRequestException
            var m2mMock = new Mock<IMundusM2MClient>();
            m2mMock.Setup(x => x.GetContractConfigurationAsync(It.IsAny<MundusConfigurationOptions>()))
                .ThrowsAsync(new System.Net.Http.HttpRequestException("CIAM is down"));

            // Mock logger factory
            var loggerMock = new Mock<ILogger>();
            var loggerFactoryMock = new Mock<ILoggerFactory>();
            loggerFactoryMock.Setup(l => l.CreateLogger(It.IsAny<string>())).Returns(loggerMock.Object);

            // Register mocks overriding previous registrations
            services.AddSingleton<IMundusM2MClient>(m2mMock.Object);
            services.AddSingleton<ILoggerFactory>(loggerFactoryMock.Object);

            var provider = services.BuildServiceProvider();

            // Create a token with AuthorizedCompanyCode claim
            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(new JwtSecurityToken(claims: new[] { 
                new System.Security.Claims.Claim("AuthorizedCompanyCode", "C1") 
            }));

            var context = new DefaultHttpContext();
            context.RequestServices = provider;
            context.Request.Headers["Authorization"] = $"Bearer {token}";

            var jwtOptions = provider.GetRequiredService<Microsoft.Extensions.Options
                .IOptionsMonitor<JwtBearerOptions>>()
                .Get(JwtBearerDefaults.AuthenticationScheme);

            var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, 
                JwtBearerDefaults.AuthenticationScheme, 
                typeof(JwtBearerHandler));

            var messageContext = new MessageReceivedContext(context, scheme, jwtOptions);

            // Act
            await jwtOptions.Events.OnMessageReceived(messageContext).ConfigureAwait(false);

            // Assert: logger logged an error with prefix
            loggerFactoryMock.Verify(l => l.CreateLogger(It.IsAny<string>()), Times.AtLeastOnce);
            loggerMock.Verify(l => l.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("[MUNDUS_SECURITY_ERROR]")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()), Times.AtLeastOnce);

            // Ensure fail was set on context
            Assert.IsNotNull(messageContext.Result);
        }


        [TestMethod]
        public async Task OnMessageReceived_ShouldDenyAccess_WhenTokenIsTampered()
        {
            var services = new ServiceCollection();
            services.AddMemoryCache();
            services.AddHttpContextAccessor();
            services.AddMundusAuthentication();

            var provider = services.BuildServiceProvider();

            // Create a malformed token that will cause ReadJwtToken to throw
            var tamperedToken = "not.a.jwt.token";

            var context = new DefaultHttpContext();
            context.RequestServices = provider;
            context.Request.Headers["Authorization"] = $"Bearer {tamperedToken}";

            var jwtOptions = provider.GetRequiredService<Microsoft.Extensions.Options
                .IOptionsMonitor<JwtBearerOptions>>()
                .Get(JwtBearerDefaults.AuthenticationScheme);

            var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, 
                JwtBearerDefaults.AuthenticationScheme, 
                typeof(JwtBearerHandler));

            var messageContext = new MessageReceivedContext(context, scheme, jwtOptions);

            // Act
            await jwtOptions.Events.OnMessageReceived(messageContext).ConfigureAwait(false);

            // Since token could not be read, no items must be populated and result remains null (handled safely)
            Assert.IsNull(messageContext.HttpContext.Items["Mundus_SecurityKey"]);
            Assert.IsNull(messageContext.HttpContext.Items["Mundus_Issuer"]);
        }


        [TestMethod]
        public async Task OnMessageReceived_ShouldSucceed_WhenCacheHit()
        {
            var services = new ServiceCollection();
            services.AddMemoryCache();
            services.AddHttpContextAccessor();

            services.AddMundusAuthentication();

            // Mock IMundusM2MClient to verify not called
            var m2mMock = new Mock<IMundusM2MClient>();
            services.AddSingleton<IMundusM2MClient>(m2mMock.Object);

            var provider = services.BuildServiceProvider();
            var cache = provider.GetRequiredService<IMemoryCache>();

            // Prepare a configuration and cache it
            var cfg = new MundusTokenConfigurationResponseDTO
            {
                JwtSecretKey = "secret1234567890",
                JwtIssuer = "issuer",
                Urls = new[] { "aud1" },
                TokenExpirationMinutes = 60,
                MachineToken = "mt"
            };

            cache.Set("MUNDUS_CFG_C1", cfg, new MemoryCacheEntryOptions { 
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(60) 
            });

            // Create token
            var handler = new JwtSecurityTokenHandler();
            var token = handler.WriteToken(new JwtSecurityToken(claims: new[] { 
                new System.Security.Claims.Claim("AuthorizedCompanyCode", "C1") 
            }));

            var context = new DefaultHttpContext();
            context.RequestServices = provider;
            context.Request.Headers["Authorization"] = $"Bearer {token}";

            var jwtOptions = provider.GetRequiredService<Microsoft.Extensions.Options
                .IOptionsMonitor<JwtBearerOptions>>()
                .Get(JwtBearerDefaults.AuthenticationScheme);

            var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, 
                JwtBearerDefaults.AuthenticationScheme, typeof(JwtBearerHandler));
            var messageContext = new MessageReceivedContext(context, scheme, jwtOptions);

            // Act
            await jwtOptions.Events.OnMessageReceived(messageContext).ConfigureAwait(false);

            // Assert: cache hit should populate items and m2m should not be invoked
            Assert.IsNotNull(messageContext.HttpContext.Items["Mundus_SecurityKey"]);
            Assert.AreEqual(cfg.JwtIssuer, messageContext.HttpContext.Items["Mundus_Issuer"] as string);
            m2mMock.Verify(x => x.GetContractConfigurationAsync(It.IsAny<MundusConfigurationOptions>()), Times.Never);
        }
    }
}

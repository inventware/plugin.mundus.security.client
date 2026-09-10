using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Mundus.Security.Client.Configuration;
using Mundus.Security.Client.DTOs;
using Mundus.Security.Client.Services;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.Json;


namespace Mundus.Security.Client.Extensions
{
    [Description("This is a static class that will contain the `AddMundusAuthentication()` extension method. It is " +
        "designed to intercept the .NET pipeline, manage a dynamic cache based on contract duration, and populate " +
        "'HttpContext.User' with the authenticated user's 'ClaimsPrincipal'.")]
    public static class MundusAuthenticationExtensions
    {
        public static IServiceCollection AddMundusAuthentication(this IServiceCollection services)
        {
            EnsureOptionsRegistered(services);

            //ConfigureM2MHttpClient(services);

            var sp = services.BuildServiceProvider();
            var httpContextAccessor = sp.GetRequiredService<IHttpContextAccessor>();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwtOptions => ConfigureJwtBearerOptions(jwtOptions, httpContextAccessor));

            return services;
        }


        private static void EnsureOptionsRegistered(IServiceCollection services)
        {
            var mundusOptions = new MundusConfigurationOptions();
            services.AddSingleton(mundusOptions);

            services.AddHttpClient<MundusHttpClient>(client => {
                client.Timeout = TimeSpan.FromMinutes(5); // Aumento temporário para 5 minutos
            });

            /// ********************************************************************************
            /// COMENTADO TEMPORARIAMENTE PARA TESTES SEM REENVIO DE REQUESTS!
            /// 888888888888888888888888888888888888888888888888888888888888888888888888888888888
            //services.AddHttpClient<MundusHttpClient>()
            //    .AddStandardResilienceHandler(options => {
            //        if (options.TotalRequestTimeout != null)
            //            options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(15);

            //        if (options.Retry != null)
            //        {
            //            options.Retry.MaxRetryAttempts = 3;
            //            options.Retry.UseJitter = true;
            //            options.Retry.Delay = TimeSpan.FromSeconds(2);
            //        }

            //        if (options.AttemptTimeout != null)
            //            options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(5);

            //        if (options.CircuitBreaker != null)
            //        {
            //            options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(30);
            //            options.CircuitBreaker.FailureRatio = 0.5;
            //        }
            //    });

            services.AddMemoryCache();

            services.AddHttpContextAccessor();
        }


        //private static void EnsureOptionsRegistered(IServiceCollection services)
        //{
        //    var mundusOptions = new MundusConfigurationOptions();

        //    services.AddSingleton(mundusOptions);

        //    services.AddHttpClient<MundusHttpClient>(client => {
        //        client.Timeout = TimeSpan.FromMinutes(5); // Aumento temporário para 5 minutos
        //    });

        //    services.AddMemoryCache();

        //    services.AddHttpContextAccessor();
        //}


        //private static void ConfigureM2MHttpClient(IServiceCollection services)
        //{
        //    var clientBuilder = services.AddHttpClient<IMundusM2MClient, MundusM2MClient>();

        //    clientBuilder.AddStandardResilienceHandler(options =>
        //    {
        //        // Total request timeout across retries
        //        if (options.TotalRequestTimeout != null){
        //            options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(15);
        //        }

        //        // Retry policy
        //        if (options.Retry != null)
        //        {
        //            options.Retry.MaxRetryAttempts = 3;
        //            options.Retry.UseJitter = true;
        //            options.Retry.Delay = TimeSpan.FromSeconds(2);
        //        }

        //        // Per-attempt timeout
        //        if (options.AttemptTimeout != null){
        //            options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(5);
        //        }

        //        // Circuit breaker
        //        if (options.CircuitBreaker != null)
        //        {
        //            options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(30);
        //            options.CircuitBreaker.FailureRatio = 0.5;
        //        }
        //    });
        //}


        private static void ConfigureJwtBearerOptions(JwtBearerOptions jwtOptions, IHttpContextAccessor 
            httpContextAccessor)
        {
            jwtOptions.RequireHttpsMetadata = true;
            jwtOptions.Events = new JwtBearerEvents {
                OnMessageReceived = context => HandleIncomingMessageAsync(context)
            };

            jwtOptions.TokenValidationParameters = ConfigureTokenValidationParameters(httpContextAccessor);
        }


        private static TokenValidationParameters ConfigureTokenValidationParameters(IHttpContextAccessor 
            httpContextAccessor)
        {
            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,

                IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                {
                    var http = httpContextAccessor.HttpContext;
                    var key = http?.Items["Mundus_SecurityKey"] as SymmetricSecurityKey;
                    if (key == null) return Enumerable.Empty<SecurityKey>();
                    return new[] { key };
                },

                AudienceValidator = (audiences, securityToken, validationParameters) =>
                {
                    var http = httpContextAccessor.HttpContext;
                    var expected = http?.Items["Mundus_Audiences"] as string[];
                    if (expected == null || expected.Length == 0) return false;
                    return audiences.Any(a => expected.Contains(a, StringComparer.OrdinalIgnoreCase));
                },

                IssuerValidator = (issuer, securityToken, validationParameters) =>
                {
                    var http = httpContextAccessor.HttpContext;
                    return http?.Items["Mundus_Issuer"] as string ?? issuer;
                }
            };
        }


        private static async Task HandleIncomingMessageAsync(MessageReceivedContext context)
        {
            var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
            var logger = loggerFactory.CreateLogger("MundusSecurity");

            try
            {
                // extract token
                var auth = context.Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)){
                    return;
                }

                var token = auth.Substring("Bearer ".Length).Trim();
                context.Token = token;

                JwtSecurityToken jwt;
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    jwt = handler.ReadJwtToken(token);
                }
                catch
                {
                    return;
                }

                var companyCode = jwt.Claims.FirstOrDefault(c => c.Type == "AuthorizedCompanyCode")?.Value;
                if (string.IsNullOrWhiteSpace(companyCode)) 
                    return;

                var configuration = await FetchAndCacheConfigurationAsync(context, companyCode).ConfigureAwait(false);
                if (configuration != null){
                    PopulateHttpContextItems(context, configuration);
                }
            }
            catch (Exception ex)
            {
                LogSecurityError(context, ex);
                return;
            }
        }


        private static async Task<MundusTokenConfigurationResponseDTO?> FetchAndCacheConfigurationAsync(
            MessageReceivedContext context, string companyCode)
        {
            var cache = context.HttpContext.RequestServices.GetService<IMemoryCache>();
            if (cache == null) 
                return null;

            var cacheKey = $"MUNDUS_CFG_{companyCode}";
            if (cache.TryGetValue(cacheKey, out MundusTokenConfigurationResponseDTO? cachedConfiguration))
                return cachedConfiguration;

            //var m2m = context.HttpContext.RequestServices.GetService<IMundusM2MClient>();
            //var opts = context.HttpContext.RequestServices.GetService<MundusConfigurationOptions>();
            //if (m2m == null || opts == null) 
            //    return null;

            //configuration = await m2m.GetContractConfigurationAsync(opts).ConfigureAwait(false);

            // Resolve new service - MundusHttpClient
            var mundusHttp = context.HttpContext.RequestServices.GetService<MundusHttpClient>();
            if (mundusHttp == null)
                return null;

            var response = await mundusHttp
                .PostToMundusSecurityAsMachineAsync<object>("m2m/connect/token", null)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return null;

            // Deserialise the HTTP response body that came from your CIAM (containing the MachineMachineKeysDTO)
            var tokenJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc = JsonDocument.Parse(tokenJson);
            var dtoElement = doc.RootElement.GetProperty("dto");

            var configuration = new MundusTokenConfigurationResponseDTO
            {
                JwtSecretKey = dtoElement.GetProperty("jwtSecretKey").GetString(),
                JwtIssuer = dtoElement.GetProperty("jwtIssuer").GetString(),
                // Map the contract expiration time dynamically to feed your entryOptions below
                TokenExpirationMinutes = dtoElement
                    .TryGetProperty("tokenExpirationMinutes", out var expProp) ? expProp.GetInt32() : 30
            };

            var entryOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(Math.Max(1, 
                    configuration.TokenExpirationMinutes))
            };

            cache.Set(cacheKey, configuration, entryOptions);

            return configuration;
        }


        private static void PopulateHttpContextItems(MessageReceivedContext context, 
            MundusTokenConfigurationResponseDTO configuration)
        {
            var keyBytes = Encoding.UTF8.GetBytes(configuration.JwtSecretKey ?? string.Empty);
            var symmetricKey = new SymmetricSecurityKey(keyBytes);
            context.HttpContext.Items["Mundus_SecurityKey"] = symmetricKey;
            context.HttpContext.Items["Mundus_Issuer"] = configuration.JwtIssuer;
            context.HttpContext.Items["Mundus_Audiences"] = configuration.Urls ?? Array.Empty<string>();
        }


        private static void LogSecurityError(MessageReceivedContext context, Exception exception)
        {
            try
            {
                var loggerFactory = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>();
                var logger = loggerFactory.CreateLogger("MundusSecurity");
                logger.LogError(exception, "[MUNDUS_SECURITY_ERROR] {Message}", exception.Message);
            }
            catch
            {
                // Swallow logging errors to avoid masking original exception.
            }

            try
            {
                context.Fail(exception);
            }
            catch
            {
                // Ignore!!!
            }
        }
    }
}

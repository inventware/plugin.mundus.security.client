using System;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Mundus.Security.Client.Configuration;
using Mundus.Security.Client.DTOs;
using Mundus.Security.Client.Services;

namespace Mundus.Security.Client.Extensions
{
    [Description("O Coração do Plugin - Esta é a classe estática que conterá o método de extensão " +
        "AddMundusAuthentication(). Deve interceptar o pipeline do .NET, gerenciando o cache dinâmico " +
        "baseado no tempo do contrato, povoando o HttpContext.User com o ClaimsPrincipal do usuário " +
        "autenticado.")]
    public static class MundusAuthenticationExtensions
    {
        public static IServiceCollection AddMundusAuthentication(this IServiceCollection services)
        {
            // força leitura das variáveis de ambiente
            var mundusOptions = new MundusConfigurationOptions();
            services.AddSingleton(mundusOptions);

            services.AddMemoryCache();
            services.AddHttpContextAccessor();

            // registra client para chamadas ao CIAM
            services.AddHttpClient<IMundusM2MClient, MundusM2MClient>();

            // obtém um IHttpContextAccessor para uso em closures do TokenValidationParameters
            var sp = services.BuildServiceProvider();
            var httpContextAccessor = sp.GetRequiredService<IHttpContextAccessor>();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(jwtOptions =>
                {
                    jwtOptions.RequireHttpsMetadata = true;

                    jwtOptions.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = async context =>
                        {
                            // captura token do cabeçalho Authorization: Bearer <token>
                            var auth = context.Request.Headers["Authorization"].FirstOrDefault();
                            if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                            {
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
                            if (string.IsNullOrWhiteSpace(companyCode)) return;

                            var cache = context.HttpContext.RequestServices.GetService<IMemoryCache>();
                            if (cache == null) return;

                            var cacheKey = $"MUNDUS_CFG_{companyCode}";
                            if (!cache.TryGetValue(cacheKey, out MundusTokenConfigurationResponseDTO configuration))
                            {
                                var m2m = context.HttpContext.RequestServices.GetService<IMundusM2MClient>();
                                var opts = context.HttpContext.RequestServices.GetService<MundusConfigurationOptions>();
                                if (m2m == null || opts == null) return;

                                configuration = await m2m.GetContractConfigurationAsync(opts).ConfigureAwait(false);

                                var entryOptions = new MemoryCacheEntryOptions
                                {
                                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(Math.Max(1, configuration.TokenExpirationMinutes))
                                };

                                cache.Set(cacheKey, configuration, entryOptions);
                            }

                            // armazena dados de validação no HttpContext.Items para serem usados pelo resolver
                            if (configuration != null)
                            {
                                var keyBytes = Encoding.UTF8.GetBytes(configuration.JwtSecretKey ?? string.Empty);
                                var symmetricKey = new SymmetricSecurityKey(keyBytes);
                                context.HttpContext.Items["Mundus_SecurityKey"] = symmetricKey;
                                context.HttpContext.Items["Mundus_Issuer"] = configuration.JwtIssuer;
                                context.HttpContext.Items["Mundus_Audiences"] = configuration.Urls ?? Array.Empty<string>();
                            }
                        }
                    };

                    jwtOptions.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateIssuerSigningKey = true,
                        ValidateLifetime = true,

                        // Resolve a chave de assinatura dinâmica que foi colocada no HttpContext.Items
                        IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
                        {
                            var http = httpContextAccessor.HttpContext;
                            var key = http?.Items["Mundus_SecurityKey"] as SymmetricSecurityKey;
                            if (key == null) return Enumerable.Empty<SecurityKey>();
                            return new[] { key };
                        },

                        // Audience validator usa as audiences populadas no Items
                        AudienceValidator = (audiences, securityToken, validationParameters) =>
                        {
                            var http = httpContextAccessor.HttpContext;
                            var expected = http?.Items["Mundus_Audiences"] as string[];
                            if (expected == null || expected.Length == 0) return false;
                            return audiences.Any(a => expected.Contains(a, StringComparer.OrdinalIgnoreCase));
                        },

                        // IssuerValidator will be resolved by normal ValidateIssuer flow; we rely on Issuer set in Items
                        IssuerSigningKey = null
                    };
                });

            return services;
        }
    }
}

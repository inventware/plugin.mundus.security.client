using Mundus.Security.Client.Configuration;
using Mundus.Security.Client.DTOs;
using System.ComponentModel;
using System.Text;
using System.Text.Json;


namespace Mundus.Security.Client.Services
{
    [Description("An encapsulated component that securely utilizes a high-performance HttpClient. It manages backend " +
        "calls to the `/m2m/connect/token` endpoint in Mundus Security whenever a cache miss occurs.")]
    public class MundusM2MClient: IMundusM2MClient
    {
        private readonly HttpClient _httpClient;

        public MundusM2MClient(HttpClient httpClient)
        {
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }


        public async Task<MundusTokenConfigurationResponseDTO> GetContractConfigurationAsync(MundusConfigurationOptions 
            options)
        {
            if (options == null) 
                throw new ArgumentNullException(nameof(options));

            var ciamUrl = Environment.GetEnvironmentVariable("MUNDUS_SECURITY_URL");
            if (string.IsNullOrWhiteSpace(ciamUrl))
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] The MUNDUS_SECURITY_URL environment " +
                    "variable was not found or is empty.");
            }

            var credentials = new MundusMachineCredentialsDTO
            {
                ClientId = options.ClientId,
                ApplicationCode = options.ApplicationCode,
                GrantType = "client_credentials"
            };

            var json = JsonSerializer.Serialize(credentials);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");

            using var response = await _httpClient.PostAsync(ciamUrl, content).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            await using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
            var result = await JsonSerializer.DeserializeAsync<MundusTokenConfigurationResponseDTO>(stream, 
                new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }).ConfigureAwait(false);

            return result ?? throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Invalid CIAM response: empty " +
                "body or unexpected format.");
        }
    }
}

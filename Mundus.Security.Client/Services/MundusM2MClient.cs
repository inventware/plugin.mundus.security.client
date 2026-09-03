using Mundus.Security.Client.Configuration;
using Mundus.Security.Client.DTOs;
using System.ComponentModel;
using System.Text;
using System.Text.Json;


namespace Mundus.Security.Client.Services
{
    [Description("Componente encapsulado que utiliza HttpClient de alta performance de forma segura. Realiza o " +
        "gerenciamento de chamadas de bastidores para o endpoint /m2m/connect/token no CIAM (mundus security), " +
        "quando ocorre um Cache Miss.")]
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
            if (options == null) throw new ArgumentNullException(nameof(options));

            var ciamUrl = Environment.GetEnvironmentVariable("MUNDUS_CIAM_URL");
            if (string.IsNullOrWhiteSpace(ciamUrl))
            {
                throw new InvalidOperationException("Erro de infraestrutura: a variável de ambiente MUNDUS_CIAM_URL " +
                    "não foi encontrada ou está vazia.");
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

            return result ?? throw new InvalidOperationException("Resposta do CIAM inválida: corpo vazio ou formato " +
                "inesperado.");
        }
    }
}

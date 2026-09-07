using Mundus.Security.Client.Configuration;
using System.Net.Http.Json;


namespace Mundus.Security.Client.Services
{
    // Dentro do seu Pacote NuGet (Solution Separada)
    public class MundusHttpClient
    {
        private readonly HttpClient _httpClient;
        private readonly MundusConfigurationOptions _options;

        // O NuGet injeta as opções e o cliente resiliente internamente. 
        // O programador do site não vê isso!
        public MundusHttpClient(HttpClient httpClient, MundusConfigurationOptions options)
        {
            _httpClient = httpClient;
            _options = options;
        }


        public string ApplicationCode => _options.ApplicationCode;

        public string CompanyCode => _options.CompanyCode;


        public async Task<HttpResponseMessage> PostToMundusSecurityAsync<T>(string relativePath, T payload)
        {
            // Lê a URL base das variáveis de ambiente e limpa barras duplicadas
            var baseUrl = Environment.GetEnvironmentVariable("MUNDUS_SECURITY_URL")?.TrimEnd('/');

            var cleanPath = relativePath.TrimStart('/');

            var targetUrl = $"{baseUrl}/{cleanPath}";

            return await _httpClient.PostAsJsonAsync(targetUrl, payload).ConfigureAwait(false);
        }
    }

}

using System.ComponentModel;


namespace Mundus.Security.Client.Configuration
{
    [Description("Objeto interno que mapeia e centraliza a leitura das 4 variáveis de ambiente obrigatórias " +
        "(MUNDUS_COMPANY_CODE, MUNDUS_APPLICATION_CODE, MUNDUS_CLIENT_ID, MUNDUS_CLIENT_SECRET) direto da memória do " +
        "processo do servidor do cliente.")]
    public sealed class MundusConfigurationOptions
    {
        public string CompanyCode { get; }
        public string ApplicationCode { get; }
        public string ClientId { get; }
        public string ClientSecret { get; }

        public string SecurityUrl { get; }

        public MundusConfigurationOptions()
        {
            CompanyCode = Environment.GetEnvironmentVariable("MUNDUS_COMPANY_CODE");
            ApplicationCode = Environment.GetEnvironmentVariable("MUNDUS_APPLICATION_CODE");
            ClientId = Environment.GetEnvironmentVariable("MUNDUS_CLIENT_ID");
            ClientSecret = Environment.GetEnvironmentVariable("MUNDUS_CLIENT_SECRET");
            SecurityUrl = Environment.GetEnvironmentVariable("MUNDUS_SECURITY_URL");

            if (string.IsNullOrWhiteSpace(CompanyCode)
                || string.IsNullOrWhiteSpace(ApplicationCode)
                || string.IsNullOrWhiteSpace(ClientId)
                || string.IsNullOrWhiteSpace(ClientSecret)
                || string.IsNullOrWhiteSpace(SecurityUrl))
            {
                throw new InvalidOperationException("(MUNDUS_INFRASTRUCTURE_ERROR) As variáveis de ambiente obrigatórias " +
                    "para a comunicação com a plataforma mundus security (MUNDUS_COMPANY_CODE, MUNDUS_APPLICATION_CODE, " +
                    "MUNDUS_CLIENT_ID, MUNDUS_CLIENT_SECRET, MUNDUS_SECURITY_URL) não foram encontradas ou estão vazias.");
            }
        }
    }
}

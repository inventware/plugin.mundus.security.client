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

        public MundusConfigurationOptions()
        {
            CompanyCode = Environment.GetEnvironmentVariable("MUNDUS_COMPANY_CODE");
            ApplicationCode = Environment.GetEnvironmentVariable("MUNDUS_APPLICATION_CODE");
            ClientId = Environment.GetEnvironmentVariable("MUNDUS_CLIENT_ID");
            ClientSecret = Environment.GetEnvironmentVariable("MUNDUS_CLIENT_SECRET");

            if (string.IsNullOrWhiteSpace(CompanyCode)
                || string.IsNullOrWhiteSpace(ApplicationCode)
                || string.IsNullOrWhiteSpace(ClientId)
                || string.IsNullOrWhiteSpace(ClientSecret))
            {
                throw new InvalidOperationException("Erro de infraestrutura: as variáveis de ambiente obrigatórias para " +
                    "Mundus (MUNDUS_COMPANY_CODE, MUNDUS_APPLICATION_CODE, MUNDUS_CLIENT_ID, MUNDUS_CLIENT_SECRET) não " +
                    "foram encontradas ou estão vazias.");
            }
        }
    }
}

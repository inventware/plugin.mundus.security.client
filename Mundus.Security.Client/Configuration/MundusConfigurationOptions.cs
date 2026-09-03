using System.ComponentModel;

namespace Mundus.Security.Client.Configuration
{
    [Description("Objeto interno que mapeia e centraliza a leitura das 4 variáveis de ambiente obrigatórias " +
        "(MUNDUS_COMPANY_CODE, MUNDUS_APPLICATION_CODE, MUNDUS_CLIENT_ID, MUNDUS_CLIENT_SECRET) direto da memória do " +
        "processo do servidor do cliente.")]
    public class MundusConfigurationOptions
    {

    }
}

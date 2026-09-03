using System.ComponentModel;


namespace Mundus.Security.Client.Services
{
    [Description("Componente encapsulado que utiliza HttpClient de alta performance de forma segura. Realiza o " +
        "gerenciamento de chamadas de bastidores para o endpoint /m2m/connect/token no CIAM (mundus security), " +
        "quando ocorre um Cache Miss.")]
    public class MundusM2MClient: IMundusM2MClient
    {

    }
}

using System.ComponentModel;


namespace Mundus.Security.Client.DTOs
{
    [Description("Objeto interno para armazenar o payload de entrada para o fluxo M2M.")]
    public class MundusMachineCredentialsDTO
    {
        public string ClientId { get; set; }

        public string ApplicationCode { get; set; }

        public string GrantType { get; set; }
    }
}

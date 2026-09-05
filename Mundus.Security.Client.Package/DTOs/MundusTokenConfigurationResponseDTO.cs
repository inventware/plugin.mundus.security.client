using System.ComponentModel;


namespace Mundus.Security.Client.DTOs
{
    [Description("Objeto interno estendido que receberá a resposta do seu CIAM contendo o Token M2M, a JwtSecretKey " +
        "limpa, o JwtIssuer e o TokenExpirationMinutes dinâmico do contrato")]
    public class MundusTokenConfigurationResponseDTO
    {
        public string MachineToken { get; set; }

        public string JwtIssuer { get; set; }

        public string JwtSecretKey { get; set; }

        public string[] Urls { get; set; }

        public int TokenExpirationMinutes { get; set; }
    }
}

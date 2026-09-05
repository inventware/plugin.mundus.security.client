using System.ComponentModel;


namespace Mundus.Security.Client.DTOs
{
    [Description("An extended internal object that will receive the response from vide mundus containing the M2M " +
        "Token, the clean JwtSecretKey, the JwtIssuer, and the dynamic TokenExpirationMinutes from the contract.")]
    public class MundusTokenConfigurationResponseDTO
    {
        public string MachineToken { get; set; }

        public string JwtIssuer { get; set; }

        public string JwtSecretKey { get; set; }

        public string[] Urls { get; set; }

        public int TokenExpirationMinutes { get; set; }
    }
}

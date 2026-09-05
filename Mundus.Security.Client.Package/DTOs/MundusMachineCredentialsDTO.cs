using System.ComponentModel;


namespace Mundus.Security.Client.DTOs
{
    [Description("Internal object to store the input payload for the M2M flow.")]
    public class MundusMachineCredentialsDTO
    {
        public string ClientId { get; set; }

        public string ApplicationCode { get; set; }

        public string GrantType { get; set; }
    }
}

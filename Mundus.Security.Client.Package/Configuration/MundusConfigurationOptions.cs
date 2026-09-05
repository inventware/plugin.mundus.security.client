using System.ComponentModel;


namespace Mundus.Security.Client.Configuration
{
    [Description("Internal object that maps and centralizes the reading of the five mandatory environment variables " +
        "(MUNDUS_COMPANY_CODE, MUNDUS_APPLICATION_CODE, MUNDUS_CLIENT_ID, MUNDUS_CLIENT_SECRET, MUNDUS_SECURITY_URL) " +
        "directly from the client server process memory.")]
    public sealed class MundusConfigurationOptions
    {
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
                throw new InvalidOperationException("(MUNDUS_INFRASTRUCTURE_ERROR) The environment variables required " +
                    "for communication with the Mundus Security platform (MUNDUS_COMPANY_CODE, MUNDUS_APPLICATION_CODE, " +
                    "MUNDUS_CLIENT_ID, MUNDUS_CLIENT_SECRET, MUNDUS_SECURITY_URL) were not found or are empty.");
            }
        }

        public string CompanyCode { get; }

        public string ApplicationCode { get; }

        public string ClientId { get; }

        public string ClientSecret { get; }

        public string SecurityUrl { get; }
    }
}

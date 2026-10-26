using System.ComponentModel;


namespace Mundus.Security.Client.Configuration
{
    [Description("Internal object that maps and centralizes the reading of the six mandatory environment variables " +
        "(MUNDUS_COMPANY_CODE, MUNDUS_APPLICATION_CODE, MUNDUS_CLIENT_ID, MUNDUS_CLIENT_SECRET, " +
        "MUNDUS_SECURITY_DESTINATION_URL, MUNDUS_SECURITY_ORIGIN_URL) directly from the client server process memory.")]
    public sealed class MundusConfigurationOptions
    {
        public MundusConfigurationOptions()
        {
            CompanyCode = GetMundusSecurityEnvironmentVariable("MUNDUS_COMPANY_CODE");
            ApplicationCode = GetMundusSecurityEnvironmentVariable("MUNDUS_APPLICATION_CODE");
            ClientId = GetMundusSecurityEnvironmentVariable("MUNDUS_CLIENT_ID");
            ClientSecret = GetMundusSecurityEnvironmentVariable("MUNDUS_CLIENT_SECRET");
            SecurityDestinationUrl = GetMundusSecurityEnvironmentVariable("MUNDUS_SECURITY_DESTINATION_URL");
            SatelliteOriginUrl = GetMundusSecurityEnvironmentVariable("MUNDUS_SECURITY_ORIGIN_URL");

            if (string.IsNullOrWhiteSpace(CompanyCode)
                || string.IsNullOrWhiteSpace(ApplicationCode)
                || string.IsNullOrWhiteSpace(ClientId)
                || string.IsNullOrWhiteSpace(ClientSecret)
                || string.IsNullOrWhiteSpace(SecurityDestinationUrl)
                || string.IsNullOrWhiteSpace(SatelliteOriginUrl))
            {
                throw new InvalidOperationException("(MUNDUS_INFRASTRUCTURE_ERROR) The environment variables required " +
                    "for communication with the Mundus Security platform (MUNDUS_COMPANY_CODE, MUNDUS_APPLICATION_CODE, " +
                    "MUNDUS_CLIENT_ID, MUNDUS_CLIENT_SECRET, MUNDUS_SECURITY_DESTINATION_URL, MUNDUS_SECURITY_ORIGIN_URL) " +
                    "were not found or are empty.");
            }
        }

        private static string? GetMundusSecurityEnvironmentVariable(string name)
        {
            // It try to read from the Process (Default for Docker, Linux, Cloud and IIS)
            string? value = Environment.GetEnvironmentVariable(name);

            // If running on Windows and not found (or outdated in the IDE cache), read from the Machine
            if (OperatingSystem.IsWindows())
            {
                var updatedValue = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Machine);
                if ((string.IsNullOrWhiteSpace(value)) ||
                    (!string.IsNullOrWhiteSpace(value) && !string.IsNullOrWhiteSpace(updatedValue) && value != updatedValue))
                {
                    value = updatedValue;
                }
            }

            return value;
        }


        public string CompanyCode { get; }

        public string ApplicationCode { get; }

        public string ClientId { get; }

        public string ClientSecret { get; }

        [Description("The URL of the Mundus Security platform where the client will send requests.")]
        public string SecurityDestinationUrl { get; }

        [Description("The contracted URL by the application client (satellite).")]
        public string SatelliteOriginUrl { get; }
    }
}

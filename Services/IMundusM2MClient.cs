using System.Threading.Tasks;
using Mundus.Security.Client.Configuration;
using Mundus.Security.Client.DTOs;

namespace Mundus.Security.Client.Services
{
    public interface IMundusM2MClient
    {
        Task<MundusTokenConfigurationResponseDTO> GetContractConfigurationAsync(MundusConfigurationOptions options);
    }
}

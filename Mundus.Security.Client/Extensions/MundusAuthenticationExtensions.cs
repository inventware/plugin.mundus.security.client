using System.ComponentModel;


namespace Mundus.Security.Client.Extensions
{
    [Description("O Coração do Plugin - Esta é a classe estática que conterá o método de extensão " +
        "AddMundusAuthentication(). Deve interceptar o pipeline do .NET, gerenciando o cache dinâmico " +
        "baseado no tempo do contrato, povoando o HttpContext.User com o ClaimsPrincipal do usuário " +
        "autenticado.")]
    public class MundusAuthenticationExtensions
    {

    }
}

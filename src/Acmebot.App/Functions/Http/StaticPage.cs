using Acmebot.App.Options;

using Azure.Functions.Worker.Extensions.HttpApi;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Options;

namespace Acmebot.App.Functions.Http;

public class StaticPage(IHttpContextAccessor httpContextAccessor, IOptions<AcmebotOptions> options) : HttpFunctionBase(httpContextAccessor)
{
    [Function($"{nameof(StaticPage)}_{nameof(Serve)}")]
    public IActionResult Serve(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "{*path}")] HttpRequest req)
    {
        if (!(IsAuthenticationEnabled || options.Value.DisableAuthentication) || User.Identity?.IsAuthenticated != true)
        {
            return Unauthorized();
        }

        return LocalStaticApp();
    }
}

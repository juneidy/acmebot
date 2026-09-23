using System.Text.Json.Serialization;

using Acmebot.Acme;
using Acmebot.Acme.Models;

namespace Acmebot.App.Acme;

public sealed class OrderDetails
{
    public required AcmeOrderResource Payload { get; init; }

    public required Uri OrderUrl { get; init; }

    // Request ID of the Key Vault pending operation this order was finalized with. Set only when ExcludeCsrBasicConstraints
    // rebuilt the CSR. Not required, so orders recorded in Durable history by earlier versions still deserialize.
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PendingOperationRequestId { get; init; }

    public static OrderDetails FromResult(AcmeResult<AcmeOrderResource> result, Uri? existingOrderUrl = null, string? pendingOperationRequestId = null)
    {
        ArgumentNullException.ThrowIfNull(result);

        return new OrderDetails
        {
            Payload = result.Resource,
            OrderUrl = result.Location ?? existingOrderUrl ?? throw new InvalidOperationException("The ACME server did not return an order URL for this request."),
            PendingOperationRequestId = pendingOperationRequestId
        };
    }
}

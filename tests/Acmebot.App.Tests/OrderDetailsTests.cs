using System.Text.Json;

using Acmebot.Acme;
using Acmebot.Acme.Models;
using Acmebot.App.Acme;

using Xunit;

namespace Acmebot.App.Tests;

public sealed class OrderDetailsTests
{
    // The options Program.cs configures for the worker, which Durable Functions uses to store activity inputs and outputs
    private static readonly JsonSerializerOptions s_durableOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        IncludeFields = true
    };

    private static readonly Uri s_orderUrl = new("https://acme.example.com/order/1");

    [Fact]
    public void FromResult_KeepsPendingOperationRequestId()
    {
        var orderDetails = OrderDetails.FromResult(CreateResult(), s_orderUrl, "request-id");

        Assert.Equal("request-id", orderDetails.PendingOperationRequestId);
    }

    [Fact]
    public void Serialize_WithoutPendingOperationRequestId_OmitsIt()
    {
        var json = JsonSerializer.Serialize(OrderDetails.FromResult(CreateResult(), s_orderUrl), s_durableOptions);

        Assert.DoesNotContain("pendingOperationRequestId", json);
    }

    [Fact]
    public void Serialize_WithPendingOperationRequestId_RoundTrips()
    {
        var json = JsonSerializer.Serialize(OrderDetails.FromResult(CreateResult(), s_orderUrl, "request-id"), s_durableOptions);

        var orderDetails = JsonSerializer.Deserialize<OrderDetails>(json, s_durableOptions);

        Assert.NotNull(orderDetails);
        Assert.Equal("request-id", orderDetails.PendingOperationRequestId);
    }

    [Fact]
    public void Deserialize_OrderRecordedByEarlierVersion_HasNoPendingOperationRequestId()
    {
        // An order stored in Durable history before the property existed
        const string json = """{"payload":{"status":"valid"},"orderUrl":"https://acme.example.com/order/1"}""";

        var orderDetails = JsonSerializer.Deserialize<OrderDetails>(json, s_durableOptions);

        Assert.NotNull(orderDetails);
        Assert.Equal(s_orderUrl, orderDetails.OrderUrl);
        Assert.Equal(AcmeOrderStatuses.Valid, orderDetails.Payload.Status);
        Assert.Null(orderDetails.PendingOperationRequestId);
    }

    private static AcmeResult<AcmeOrderResource> CreateResult() => new()
    {
        Resource = new AcmeOrderResource { Status = AcmeOrderStatuses.Valid }
    };
}

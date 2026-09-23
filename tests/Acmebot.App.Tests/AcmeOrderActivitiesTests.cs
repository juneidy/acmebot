using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

using Acmebot.Acme;
using Acmebot.Acme.Models;
using Acmebot.App.Acme;
using Acmebot.App.Extensions;
using Acmebot.App.Functions.Orchestration;
using Acmebot.App.Models;

using Azure;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

using Microsoft.Extensions.Logging.Abstractions;

using Xunit;

namespace Acmebot.App.Tests;

public sealed class AcmeOrderActivitiesTests
{
    [Fact]
    public async Task CreateOrderAsync_WithAlreadyReplacedProblem_RetriesWithoutReplaces()
    {
        var directoryUrl = new Uri("https://example.com/acme/directory");
        var newNonceUrl = new Uri("https://example.com/acme/new-nonce");
        var newOrderUrl = new Uri("https://example.com/acme/new-order");
        var orderUrl = new Uri("https://example.com/acme/order/1");
        using var signer = AcmeSigner.CreateP256();
        using var handler = new RecordingHandler();
        using var httpClient = new HttpClient(handler);
        using var client = new AcmeClient(httpClient, directoryUrl);

        handler.Enqueue(_ => CreateJsonResponse(HttpStatusCode.OK, new
        {
            newNonce = newNonceUrl,
            newAccount = new Uri("https://example.com/acme/new-account"),
            newOrder = newOrderUrl,
            renewalInfo = new Uri("https://example.com/acme/renewal-info")
        }));
        var directory = await client.GetDirectoryAsync(TestContext.Current.CancellationToken);
        handler.Enqueue(_ => CreateResponse(HttpStatusCode.OK, string.Empty, contentType: null, replayNonce: "bm9uY2Ux"));
        handler.Enqueue(_ => CreateJsonResponse(
            HttpStatusCode.BadRequest,
            new
            {
                type = AcmeProblemTypes.AlreadyReplaced.Value,
                detail = "already replaced"
            },
            replayNonce: "bm9uY2Uy",
            contentType: "application/problem+json"));
        handler.Enqueue(_ => CreateJsonResponse(
            HttpStatusCode.Created,
            new
            {
                status = "pending",
                authorizations = new[] { "https://example.com/acme/authz/1" },
                finalize = "https://example.com/acme/finalize/1"
            },
            replayNonce: "bm9uY2Uz",
            location: orderUrl));
        var context = new AcmeClientContext
        {
            Client = client,
            Directory = directory,
            Signer = signer,
            Account = CreateAccountHandle(signer)
        };

        var result = await AcmeOrderActivities.CreateOrderAsync(
            context,
            ["example.com"],
            profile: "tlsserver",
            replaces: "old-cert-id",
            NullLogger<AcmeOrderActivities>.Instance);

        var postRequests = handler.Requests.Where(x => x.Method == HttpMethod.Post).ToArray();
        Assert.Equal(2, postRequests.Length);
        Assert.Equal(orderUrl, result.OrderUrl);
        Assert.Equal(AcmeOrderStatuses.Pending, result.Payload.Status);

        using var firstPayload = postRequests[0].GetPayloadJson();
        using var secondPayload = postRequests[1].GetPayloadJson();
        Assert.Equal("old-cert-id", firstPayload.RootElement.GetProperty("replaces").GetString());
        Assert.Equal("tlsserver", firstPayload.RootElement.GetProperty("profile").GetString());
        Assert.False(secondPayload.RootElement.TryGetProperty("replaces", out _));
        Assert.Equal("tlsserver", secondPayload.RootElement.GetProperty("profile").GetString());
    }

    [Fact]
    public void CreateOrderInvalidException_WithoutProblems_ReportsMissingProblemInsteadOfThrowing()
    {
        var exception = AcmeOrderActivities.CreateOrderInvalidException([]);

        var invalidOperationException = Assert.IsType<InvalidOperationException>(exception);
        Assert.Contains("did not report a problem", invalidOperationException.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateOrderInvalidException_WithOnlyDnsProblems_IsRetriable()
    {
        var exception = AcmeOrderActivities.CreateOrderInvalidException(
        [
            new AcmeProblemDetails { Type = AcmeProblemTypes.Dns },
            new AcmeProblemDetails { Type = AcmeProblemTypes.Dns }
        ]);

        Assert.IsType<RetriableOrchestratorException>(exception);
    }

    [Fact]
    public void CreateOrderInvalidException_WithNonDnsProblem_ReportsLastProblem()
    {
        var exception = AcmeOrderActivities.CreateOrderInvalidException(
        [
            new AcmeProblemDetails { Type = AcmeProblemTypes.Dns },
            new AcmeProblemDetails { Type = AcmeProblemTypes.Caa, Detail = "caa forbids issuance" }
        ]);

        var invalidOperationException = Assert.IsType<InvalidOperationException>(exception);
        Assert.Contains("caa forbids issuance", invalidOperationException.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WithUsableCertificate_SignsWithCurrentKey()
    {
        using var key = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient(TestCertificateName);
        certificateClient.Current = certificateClient.CreateVersion(key);
        var policyItem = CreatePolicyItem();
        var signers = new SignerRecorder(certificateClient);

        var csr = await CreateCsrWithoutBasicConstraintsAsync(certificateClient, policyItem, signers);

        Assert.Equal(["get-certificate", "create:Unknown"], certificateClient.Events);

        var create = Assert.Single(certificateClient.Creates);
        Assert.Equal(WellKnownIssuerNames.Unknown, create.IssuerName);
        Assert.True(create.ReuseKey);
        Assert.True(create.PreserveCertificateOrder);
        Assert.Equal(policyItem.DnsNames, create.DnsNames);
        AssertTags(policyItem.ToCertificateTags(s_acmeEndpoint), create.Tags);

        Assert.Equal(certificateClient.Current.KeyId, Assert.Single(signers.KeyIds));
        Assert.Single(Assert.Single(signers.Signers).Algorithms);
        AssertRebuiltCsr(csr, key, policyItem.DnsNames);
    }

    [Fact]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WithCertificateNotFound_CreatesSelfSignedKeyHolder()
    {
        var certificateClient = new FakeCertificateClient(TestCertificateName);
        var policyItem = CreatePolicyItem();
        var signers = new SignerRecorder(certificateClient);

        var csr = await CreateCsrWithoutBasicConstraintsAsync(certificateClient, policyItem, signers);

        Assert.Equal(["get-certificate", "get-pending", "create:Self", "create:Unknown"], certificateClient.Events);

        var holder = certificateClient.Creates[0];
        Assert.False(holder.ReuseKey);
        AssertTags(policyItem.ToCertificateTags(s_acmeEndpoint), holder.Tags);
        Assert.True(certificateClient.Creates[1].ReuseKey);

        var current = Assert.IsType<FakeCertificateVersion>(certificateClient.Current);
        Assert.Equal(current.KeyId, Assert.Single(signers.KeyIds));
        AssertRebuiltCsr(csr, current.Key, policyItem.DnsNames);
    }

    [Theory]
    [InlineData("MissingCer")]
    [InlineData("Disabled")]
    [InlineData("NotYetValid")]
    [InlineData("Expired")]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WithUnusableCertificate_CreatesSelfSignedKeyHolder(string state)
    {
        using var key = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient(TestCertificateName);
        var now = DateTimeOffset.UtcNow;
        var usable = certificateClient.CreateVersion(key);

        certificateClient.Current = state switch
        {
            "MissingCer" => usable with { Cer = null },
            "Disabled" => usable with { Enabled = false },
            "NotYetValid" => certificateClient.CreateVersion(key, now.AddDays(1), now.AddDays(30)),
            "Expired" => certificateClient.CreateVersion(key, now.AddDays(-30), now.AddDays(-1)),
            _ => throw new ArgumentOutOfRangeException(nameof(state))
        };

        var policyItem = CreatePolicyItem();

        var csr = await CreateCsrWithoutBasicConstraintsAsync(certificateClient, policyItem, new SignerRecorder(certificateClient));

        Assert.Equal(WellKnownIssuerNames.Self, certificateClient.Creates[0].IssuerName);

        var current = Assert.IsType<FakeCertificateVersion>(certificateClient.Current);
        Assert.NotSame(key, current.Key);
        AssertRebuiltCsr(csr, current.Key, policyItem.DnsNames);
    }

    [Fact]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WhenKeyVaultDoesNotReuseKey_ThrowsWithoutSigning()
    {
        using var key = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient(TestCertificateName) { IgnoreReuseKey = true };
        certificateClient.Current = certificateClient.CreateVersion(key);
        var signers = new SignerRecorder(certificateClient);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateCsrWithoutBasicConstraintsAsync(certificateClient, CreatePolicyItem(), signers));

        Assert.Contains("did not reuse the current key", exception.Message);
        Assert.Empty(signers.Signers);
    }

    [Fact]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WhenCertificateLookupFails_PropagatesWithoutChanges()
    {
        var certificateClient = new FakeCertificateClient(TestCertificateName)
        {
            GetCertificateException = new RequestFailedException(403, "Forbidden")
        };
        var signers = new SignerRecorder(certificateClient);

        var exception = await Assert.ThrowsAsync<RequestFailedException>(() => CreateCsrWithoutBasicConstraintsAsync(certificateClient, CreatePolicyItem(), signers));

        Assert.Equal(403, exception.Status);
        Assert.Equal(["get-certificate"], certificateClient.Events);
        Assert.Empty(signers.Signers);
    }

    [Fact]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WithInProgressPendingOperationForCurrentKey_ReusesIt()
    {
        using var key = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient(TestCertificateName);
        certificateClient.Current = certificateClient.CreateVersion(key);
        certificateClient.Pending = FakeCertificateClient.CreatePendingOperation(key, "inProgress");
        var policyItem = CreatePolicyItem();

        var csr = await CreateCsrWithoutBasicConstraintsAsync(certificateClient, policyItem, new SignerRecorder(certificateClient));

        Assert.Equal(["get-certificate", "create:Unknown", "conflict", "get-pending"], certificateClient.Events);
        AssertRebuiltCsr(csr, key, policyItem.DnsNames);
    }

    [Fact]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WithInProgressPendingOperationForOtherKey_ReplacesIt()
    {
        using var key = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient(TestCertificateName);
        certificateClient.Current = certificateClient.CreateVersion(key);
        certificateClient.Pending = FakeCertificateClient.CreatePendingOperation(otherKey, "inProgress");
        var policyItem = CreatePolicyItem();

        var csr = await CreateCsrWithoutBasicConstraintsAsync(certificateClient, policyItem, new SignerRecorder(certificateClient));

        Assert.Equal(["get-certificate", "create:Unknown", "conflict", "get-pending", "delete:inProgress", "create:Unknown"], certificateClient.Events);
        AssertRebuiltCsr(csr, key, policyItem.DnsNames);
    }

    [Fact]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WithUnusableCertificateAndInProgressPendingOperation_DeletesItBeforeCreatingKeyHolder()
    {
        using var key = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient(TestCertificateName);
        var now = DateTimeOffset.UtcNow;
        certificateClient.Current = certificateClient.CreateVersion(key, now.AddDays(-30), now.AddDays(-1));
        certificateClient.Pending = FakeCertificateClient.CreatePendingOperation(otherKey, "inProgress");

        await CreateCsrWithoutBasicConstraintsAsync(certificateClient, CreatePolicyItem(), new SignerRecorder(certificateClient));

        Assert.Equal(["get-certificate", "get-pending", "delete:inProgress", "create:Self", "create:Unknown"], certificateClient.Events);
    }

    [Fact]
    public async Task CreateCsrWithoutBasicConstraintsAsync_WithUnusableCertificateAndCompletedPendingOperation_DeletesIt()
    {
        using var key = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient(TestCertificateName);
        var now = DateTimeOffset.UtcNow;
        certificateClient.Current = certificateClient.CreateVersion(key, now.AddDays(-30), now.AddDays(-1));
        certificateClient.Pending = FakeCertificateClient.CreatePendingOperation(key, "completed");

        await CreateCsrWithoutBasicConstraintsAsync(certificateClient, CreatePolicyItem(), new SignerRecorder(certificateClient));

        Assert.Equal(["get-certificate", "get-pending", "delete:completed", "create:Self", "create:Unknown"], certificateClient.Events);
    }

    private const string TestCertificateName = "example-com";

    private static readonly Uri s_acmeEndpoint = new("https://acme.example.com/directory");

    private static CertificatePolicyItem CreatePolicyItem(params string[] dnsNames) => new()
    {
        CertificateName = TestCertificateName,
        DnsNames = dnsNames.Length > 0 ? dnsNames : [.. TestCertificates.DefaultDnsNames],
        DnsProviderName = "Test DNS",
        KeyType = "RSA",
        KeySize = 2048
    };

    private static Task<byte[]> CreateCsrWithoutBasicConstraintsAsync(FakeCertificateClient certificateClient, CertificatePolicyItem policyItem, SignerRecorder signers) =>
        AcmeOrderActivities.CreateCsrWithoutBasicConstraintsAsync(certificateClient, signers.Create, policyItem, s_acmeEndpoint, NullLogger.Instance, TestContext.Current.CancellationToken);

    private static void AssertRebuiltCsr(byte[] csr, AsymmetricAlgorithm expectedKey, IReadOnlyList<string> expectedDnsNames)
    {
        // Loading validates the self-signature
        var request = CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        Assert.True(KeyVaultCsrSigner.HasSamePublicKey(new PublicKey(expectedKey), request.PublicKey));
        Assert.Equal($"CN={expectedDnsNames[0]}", request.SubjectName.Name);
        Assert.DoesNotContain(request.CertificateExtensions, x => x.Oid?.Value == "2.5.29.19");
        Assert.True(Assert.Single(request.CertificateExtensions, x => x.Oid?.Value == "2.5.29.15").Critical);

        var subjectAlternativeNames = new X509SubjectAlternativeNameExtension(Assert.Single(request.CertificateExtensions, x => x.Oid?.Value == "2.5.29.17").RawData);

        Assert.Equal(expectedDnsNames, subjectAlternativeNames.EnumerateDnsNames());
    }

    private static void AssertTags(IDictionary<string, string> expected, IReadOnlyDictionary<string, string> actual) =>
        Assert.Equal(expected.OrderBy(x => x.Key), actual.OrderBy(x => x.Key));

    private sealed class SignerRecorder(FakeCertificateClient certificateClient, Exception? signException = null)
    {
        public List<Uri> KeyIds { get; } = [];

        public List<FakeCryptographyClient> Signers { get; } = [];

        public CryptographyClient Create(Uri keyId)
        {
            KeyIds.Add(keyId);

            var signer = new FakeCryptographyClient(certificateClient.GetKey(keyId), signException);

            Signers.Add(signer);

            return signer;
        }
    }

    private static AcmeAccountHandle CreateAccountHandle(AcmeSigner signer)
    {
        return new AcmeAccountHandle
        {
            AccountUrl = new Uri("https://example.com/acme/account/1"),
            Signer = signer,
            Account = new AcmeAccountResource
            {
                Status = AcmeAccountStatuses.Valid
            }
        };
    }

    private static HttpResponseMessage CreateJsonResponse<T>(HttpStatusCode statusCode, T payload, string? replayNonce = null, Uri? location = null, string contentType = "application/json")
    {
        return CreateResponse(statusCode, JsonSerializer.Serialize(payload), contentType, replayNonce, location);
    }

    private static HttpResponseMessage CreateResponse(HttpStatusCode statusCode, string content, string? contentType, string? replayNonce = null, Uri? location = null)
    {
        var response = new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(content, Encoding.ASCII)
        };

        response.Content.Headers.ContentType = contentType is null ? null : new MediaTypeHeaderValue(contentType);
        response.Headers.Location = location;

        if (replayNonce is not null)
        {
            response.Headers.TryAddWithoutValidation("Replay-Nonce", replayNonce);
        }

        return response;
    }

    private static string DecodeBase64UrlUtf8(string value) => Encoding.UTF8.GetString(Base64Url.DecodeFromChars(value));

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> _responses = new();

        public List<RecordedRequest> Requests { get; } = [];

        public void Enqueue(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) => _responses.Enqueue(responseFactory);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(await RecordedRequest.CreateAsync(request, cancellationToken));

            return _responses.TryDequeue(out var responseFactory)
                ? responseFactory(request)
                : throw new InvalidOperationException("No response was configured for the HTTP request.");
        }
    }

    private sealed record RecordedRequest(HttpMethod Method, Uri? RequestUri, string? Content)
    {
        public AcmeSignedMessage GetSignedMessage()
        {
            return JsonSerializer.Deserialize<AcmeSignedMessage>(Content!)
                ?? throw new InvalidOperationException("The request body did not contain a signed ACME message.");
        }

        public JsonDocument GetPayloadJson() => JsonDocument.Parse(DecodeBase64UrlUtf8(GetSignedMessage().Payload));

        public static async Task<RecordedRequest> CreateAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return new RecordedRequest(
                request.Method,
                request.RequestUri,
                request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken));
        }
    }
}

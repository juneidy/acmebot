using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Certificates;

namespace Acmebot.App.Tests;

internal sealed record FakeCertificateVersion(
    AsymmetricAlgorithm Key,
    byte[]? Cer,
    Uri? KeyId,
    bool? Enabled,
    DateTimeOffset? NotBefore,
    DateTimeOffset? ExpiresOn,
    DateTimeOffset? CreatedOn,
    IReadOnlyDictionary<string, string> Tags);

internal sealed record FakePendingOperation(
    AsymmetricAlgorithm Key,
    string Status,
    byte[] Csr,
    IReadOnlyDictionary<string, string> Tags,
    bool CancellationRequested = false);

internal sealed record FakeCreateRequest(
    string IssuerName,
    bool? ReuseKey,
    bool? PreserveCertificateOrder,
    IReadOnlyList<string> DnsNames,
    IReadOnlyDictionary<string, string> Tags);

// Models Key Vault for a single certificate name. Creating a version fails with 409 only while the pending
// operation is in progress, and replaces a completed, failed or cancelled one:
// https://learn.microsoft.com/azure/key-vault/certificates/create-certificate-scenarios
internal sealed class FakeCertificateClient(string name) : CertificateClient
{
    public static readonly Uri FakeVaultUri = new("https://example.vault.azure.net/");

    private readonly Dictionary<Uri, AsymmetricAlgorithm> _keys = [];
    private int _versionCount;

    public string CertificateName => name;

    public FakeCertificateVersion? Current { get; set; }

    public FakePendingOperation? Pending { get; set; }

    public List<string> Events { get; } = [];

    public List<FakeCreateRequest> Creates { get; } = [];

    // Key Vault creates a new key even though the policy asks to reuse the current one
    public bool IgnoreReuseKey { get; set; }

    // Every create fails with a 409 that is not caused by a pending operation, such as a soft-deleted certificate
    public bool ConflictWithoutPendingOperation { get; set; }

    public Exception? GetCertificateException { get; set; }

    // Runs once, just before the next pending operation lookup, to model a change made by a concurrent run
    public Action? BeforeNextGetPendingOperation { get; set; }

    public FakeCertificateVersion CreateVersion(
        AsymmetricAlgorithm key,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? expiresOn = null,
        IReadOnlyDictionary<string, string>? tags = null,
        byte[]? cer = null)
    {
        var now = DateTimeOffset.UtcNow;
        var validFrom = notBefore ?? now.AddDays(-1);
        var validTo = expiresOn ?? now.AddDays(30);
        var keyId = new Uri(FakeVaultUri, $"keys/{name}/{++_versionCount:x8}");

        _keys[keyId] = key;

        return new FakeCertificateVersion(
            key,
            cer ?? TestCertificates.CreateSelfSignedCertificate(key, validFrom, validTo),
            keyId,
            true,
            validFrom,
            validTo,
            now,
            tags ?? new Dictionary<string, string>());
    }

    public static FakePendingOperation CreatePendingOperation(
        AsymmetricAlgorithm key,
        string status,
        IReadOnlyList<string>? dnsNames = null,
        IReadOnlyDictionary<string, string>? tags = null,
        bool cancellationRequested = false) =>
        new(key, status, TestCertificates.CreateKeyVaultStyleCsr(key, dnsNames), tags ?? new Dictionary<string, string>(), cancellationRequested);

    public AsymmetricAlgorithm GetKey(Uri keyId) => _keys[keyId];

    public KeyVaultCertificateWithPolicy ToKeyVaultCertificate(FakeCertificateVersion version)
    {
        var properties = CertificateModelFactory.CertificateProperties(
            id: new Uri(FakeVaultUri, $"certificates/{name}/{version.KeyId?.Segments[^1] ?? "0"}"),
            name: name,
            vaultUri: FakeVaultUri,
            version: version.KeyId?.Segments[^1],
            x509thumbprint: null,
            notBefore: version.NotBefore,
            expiresOn: version.ExpiresOn,
            createdOn: version.CreatedOn,
            updatedOn: version.CreatedOn,
            recoveryLevel: null,
            recoverableDays: null);

        properties.Enabled = version.Enabled;

        foreach (var tag in version.Tags)
        {
            properties.Tags[tag.Key] = tag.Value;
        }

        return CertificateModelFactory.KeyVaultCertificateWithPolicy(properties, keyId: version.KeyId, secretId: null, cer: version.Cer, policy: null);
    }

    public override Task<Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string certificateName, CancellationToken cancellationToken = default)
    {
        Events.Add("get-certificate");

        if (GetCertificateException is not null)
        {
            return Task.FromException<Response<KeyVaultCertificateWithPolicy>>(GetCertificateException);
        }

        return Current is null
            ? Task.FromException<Response<KeyVaultCertificateWithPolicy>>(new RequestFailedException(404, "Certificate not found."))
            : Task.FromResult(Response.FromValue(ToKeyVaultCertificate(Current), new StubResponse(200)));
    }

    public override Task<CertificateOperation> StartCreateCertificateAsync(
        string certificateName,
        CertificatePolicy policy,
        bool? enabled = null,
        IDictionary<string, string>? tags = null,
        bool? preserveCertificateOrder = null,
        CancellationToken cancellationToken = default)
    {
        var requestedTags = new Dictionary<string, string>(tags ?? new Dictionary<string, string>());
        var dnsNames = policy.SubjectAlternativeNames?.DnsNames.ToArray() ?? [];

        Creates.Add(new FakeCreateRequest(policy.IssuerName, policy.ReuseKey, preserveCertificateOrder, dnsNames, requestedTags));
        Events.Add($"create:{policy.IssuerName}");

        if (ConflictWithoutPendingOperation || string.Equals(Pending?.Status, "inProgress", StringComparison.OrdinalIgnoreCase))
        {
            Events.Add("conflict");

            return Task.FromException<CertificateOperation>(new RequestFailedException(409, "A new key vault certificate can not be created or imported while a pending key vault certificate's status is inProgress."));
        }

        var key = policy.ReuseKey == true && Current is not null && !IgnoreReuseKey ? Current.Key : RSA.Create(2048);

        if (policy.IssuerName == WellKnownIssuerNames.Self)
        {
            var now = DateTimeOffset.UtcNow;
            var notBefore = now.AddMinutes(-5);
            var notAfter = now.AddMonths(policy.ValidityInMonths ?? 12);

            Current = CreateVersion(key, notBefore, notAfter, requestedTags, TestCertificates.CreateSelfSignedCertificate(key, notBefore, notAfter, policy.Subject));
            Pending = CreatePendingOperation(key, "completed", dnsNames, requestedTags);
        }
        else
        {
            Pending = CreatePendingOperation(key, "inProgress", dnsNames, requestedTags);
        }

        return Task.FromResult<CertificateOperation>(new FakeCertificateOperation(this, Pending));
    }

    public override Task<CertificateOperation> GetCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default)
    {
        var beforeGet = BeforeNextGetPendingOperation;

        BeforeNextGetPendingOperation = null;
        beforeGet?.Invoke();

        Events.Add("get-pending");

        return Pending is null
            ? Task.FromException<CertificateOperation>(new RequestFailedException(404, "Pending certificate not found."))
            : Task.FromResult<CertificateOperation>(new FakeCertificateOperation(this, Pending));
    }

    internal Task DeletePendingOperationAsync(FakePendingOperation pendingOperation)
    {
        Events.Add($"delete:{pendingOperation.Status}");

        if (!ReferenceEquals(Pending, pendingOperation))
        {
            return Task.FromException(new RequestFailedException(404, "Pending certificate not found."));
        }

        Pending = null;

        return Task.CompletedTask;
    }
}

// HasCompleted is left to the SDK, so it stays false after a lookup exactly as it does against the real service
internal sealed class FakeCertificateOperation(FakeCertificateClient certificateClient, FakePendingOperation pendingOperation) : CertificateOperation
{
    public override CertificateOperationProperties Properties => CertificateModelFactory.CertificateOperationProperties(
        id: new Uri(FakeCertificateClient.FakeVaultUri, $"certificates/{certificateClient.CertificateName}/pending"),
        name: certificateClient.CertificateName,
        vaultUri: FakeCertificateClient.FakeVaultUri,
        issuerName: WellKnownIssuerNames.Unknown,
        certificateType: null,
        certificateTransparency: null,
        csr: pendingOperation.Csr,
        cancellationRequested: pendingOperation.CancellationRequested,
        requestId: "request-id",
        status: pendingOperation.Status,
        statusDetails: null,
        target: null,
        error: null);

    public override Task DeleteAsync(CancellationToken cancellationToken = default) => certificateClient.DeletePendingOperationAsync(pendingOperation);

    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(CancellationToken cancellationToken = default)
    {
        var current = certificateClient.Current ?? throw new InvalidOperationException("The certificate operation did not complete.");

        return ValueTask.FromResult(Response.FromValue(certificateClient.ToKeyVaultCertificate(current), new StubResponse(200)));
    }
}

internal sealed class StubResponse(int status) : Response
{
    public override int Status => status;

    public override string ReasonPhrase => string.Empty;

    public override Stream? ContentStream { get; set; }

    public override string ClientRequestId { get; set; } = string.Empty;

    public override void Dispose()
    {
    }

    protected override bool ContainsHeader(string name) => false;

    protected override IEnumerable<HttpHeader> EnumerateHeaders() => [];

    protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
    {
        value = null;

        return false;
    }

    protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
    {
        values = null;

        return false;
    }
}

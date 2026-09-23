using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

using Acmebot.Acme;
using Acmebot.Acme.Models;
using Acmebot.App.Acme;
using Acmebot.App.Extensions;
using Acmebot.App.Models;
using Acmebot.App.Options;

using Azure.Core;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Acmebot.App.Functions.Orchestration;

public partial class AcmeOrderActivities(
    AcmeClientFactory acmeClientFactory,
    CertificateClient certificateClient,
    TokenCredential credential,
    IOptions<AcmebotOptions> options,
    ILogger<AcmeOrderActivities> logger)
{
    private readonly AcmebotOptions _options = options.Value;

    [Function(nameof(Order))]
    public async Task<OrderDetails> Order([ActivityTrigger] (IReadOnlyList<string>, string?, string?) input)
    {
        var (dnsNames, requestedReplaces, requestedProfile) = input;

        var acmeContext = await acmeClientFactory.CreateClientAsync();
        var replaces = acmeContext.Directory.RenewalInfo is not null ? requestedReplaces : null;
        var profile = NormalizeProfile(requestedProfile) ?? NormalizeProfile(_options.PreferredProfile);

        return await CreateOrderAsync(acmeContext, dnsNames, profile, replaces, logger);
    }

    [Function(nameof(AnswerChallenges))]
    public async Task AnswerChallenges([ActivityTrigger] IReadOnlyList<AcmeChallengeResult> challengeResults)
    {
        var acmeContext = await acmeClientFactory.CreateClientAsync();

        foreach (var challengeResult in challengeResults)
        {
            await acmeContext.Client.AnswerChallengeAsync(acmeContext.Account, challengeResult.Url);
        }
    }

    [Function(nameof(CheckIsReady))]
    public async Task CheckIsReady([ActivityTrigger] (OrderDetails, IReadOnlyList<AcmeChallengeResult>) input)
    {
        var (orderDetails, challengeResults) = input;

        var acmeContext = await acmeClientFactory.CreateClientAsync();
        var acmeClient = acmeContext.Client;

        orderDetails = OrderDetails.FromResult(await acmeClient.GetOrderAsync(acmeContext.Account, orderDetails.OrderUrl), orderDetails.OrderUrl);

        if (orderDetails.Payload.Status == AcmeOrderStatuses.Invalid)
        {
            var problems = new List<AcmeProblemDetails>();

            foreach (var challengeResult in challengeResults)
            {
                var challenge = (await acmeClient.GetChallengeAsync(acmeContext.Account, challengeResult.Url)).Resource;

                if (challenge.Status != AcmeChallengeStatuses.Invalid || challenge.Error is null)
                {
                    continue;
                }

                LogAcmeDomainValidationError(logger, JsonSerializer.Serialize(challenge.Error));

                problems.Add(challenge.Error);
            }

            // The certificate authority does not always attach the failure to a challenge, so fall back
            // to the order-level problem before giving up on reporting a cause.
            if (problems.Count == 0 && orderDetails.Payload.Error is { } orderError)
            {
                LogAcmeDomainValidationError(logger, JsonSerializer.Serialize(orderError));

                problems.Add(orderError);
            }

            throw CreateOrderInvalidException(problems);
        }

        if (orderDetails.Payload.Status != AcmeOrderStatuses.Ready)
        {
            throw new RetriableActivityException($"ACME validation is still in progress. Current order status: {orderDetails.Payload.Status}. The operation will be retried automatically.");
        }
    }

    [Function(nameof(FinalizeOrder))]
    public async Task<OrderDetails> FinalizeOrder([ActivityTrigger] (CertificatePolicyItem, OrderDetails) input)
    {
        var (certificatePolicyItem, orderDetails) = input;

        var csr = _options.ExcludeCsrBasicConstraints
            ? await CreateCsrWithoutBasicConstraintsAsync(certificateClient, keyId => new CryptographyClient(keyId, credential), certificatePolicyItem, _options.Endpoint, logger)
            : await CreateKeyVaultCsrAsync(certificatePolicyItem);

        var acmeContext = await acmeClientFactory.CreateClientAsync();

        return OrderDetails.FromResult(
            await acmeContext.Client.FinalizeOrderAsync(
                acmeContext.Account,
                orderDetails.Payload.Finalize ?? throw new InvalidOperationException("The ACME order did not include a finalize URL."),
                csr),
            orderDetails.OrderUrl);
    }

    [Function(nameof(CheckIsValid))]
    public async Task<OrderDetails> CheckIsValid([ActivityTrigger] OrderDetails orderDetails)
    {
        var acmeContext = await acmeClientFactory.CreateClientAsync();

        orderDetails = OrderDetails.FromResult(await acmeContext.Client.GetOrderAsync(acmeContext.Account, orderDetails.OrderUrl), orderDetails.OrderUrl);

        if (orderDetails.Payload.Status == AcmeOrderStatuses.Invalid)
        {
            throw new InvalidOperationException("The ACME order became invalid during finalization. Review the reported problem and retry the operation.");
        }

        if (orderDetails.Payload.Status != AcmeOrderStatuses.Valid)
        {
            throw new RetriableActivityException($"ACME order finalization is still in progress. Current order status: {orderDetails.Payload.Status}. The operation will be retried automatically.");
        }

        return orderDetails;
    }

    [Function(nameof(MergeCertificate))]
    public async Task<CertificateItem> MergeCertificate([ActivityTrigger] (string, OrderDetails) input)
    {
        var (certificateName, orderDetails) = input;

        var acmeContext = await acmeClientFactory.CreateClientAsync();

        var x509Certificates = await acmeContext.Client.GetOrderCertificateAsync(acmeContext.Account, orderDetails, _options.PreferredChain);

        var mergeCertificateOptions = new MergeCertificateOptions(
            certificateName,
            // Key Vault exports the merged chain in reverse order, so submit it issuer-most-first to produce leaf-first PFX/PEM output.
            x509Certificates
                .Cast<X509Certificate2>()
                .Reverse()
                .Select(static certificate => certificate.RawData)
                .ToArray()
        );

        var mergedCertificate = (await certificateClient.MergeCertificateAsync(mergeCertificateOptions)).Value;

        // ARI による更新判定に使う ACME Certificate Identifier (AKI + Serial) をタグに保存する
        var certificateIdentifier = AcmeClient.CreateCertificateIdentifier(x509Certificates[0]);

        mergedCertificate.Properties.Tags.SetCertificateId(certificateIdentifier);

        await certificateClient.UpdateCertificatePropertiesAsync(mergedCertificate.Properties);

        return mergedCertificate.ToCertificateItem();
    }

    private async Task<byte[]> CreateKeyVaultCsrAsync(CertificatePolicyItem certificatePolicyItem)
    {
        try
        {
            var certificatePolicy = certificatePolicyItem.ToCertificatePolicy();
            var tags = certificatePolicyItem.ToCertificateTags(_options.Endpoint);

            var certificateOperation = await certificateClient.StartCreateCertificateAsync(
                certificatePolicyItem.CertificateName,
                certificatePolicy,
                tags: tags,
                preserveCertificateOrder: true);

            return certificateOperation.Properties.Csr;
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == (int)HttpStatusCode.Conflict)
        {
            var certificateOperation = await certificateClient.GetCertificateOperationAsync(certificatePolicyItem.CertificateName);

            return certificateOperation.Properties.Csr;
        }
    }

    // Key Vault always adds Basic Constraints to the CSR it generates, and the Keys API can only sign with the key of a completed
    // certificate version. So the CSR is rebuilt without the extension, signed with the current version's key, and the issued
    // certificate is merged into a new version that reuses that key.
    internal static async Task<byte[]> CreateCsrWithoutBasicConstraintsAsync(
        CertificateClient certificateClient,
        Func<Uri, CryptographyClient> cryptographyClientFactory,
        CertificatePolicyItem certificatePolicyItem,
        Uri endpoint,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        var signingCertificate = await GetSigningCertificateAsync(certificateClient, certificatePolicyItem.CertificateName, cancellationToken)
                                 ?? await CreateSelfSignedCertificateAsync(certificateClient, certificatePolicyItem, endpoint, logger, cancellationToken);

        using var x509Certificate = X509CertificateLoader.LoadCertificate(signingCertificate.Cer);

        var certificateOperation = await StartReuseKeyCertificateOperationAsync(certificateClient, certificatePolicyItem, endpoint, x509Certificate.PublicKey, logger, cancellationToken);

        var cryptographyClient = cryptographyClientFactory(signingCertificate.KeyId);

        try
        {
            return KeyVaultCsrSigner.RebuildWithoutBasicConstraints(certificateOperation.Properties.Csr, cryptographyClient);
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == (int)HttpStatusCode.Forbidden)
        {
            throw new InvalidOperationException("Key Vault denied signing the CSR. ExcludeCsrBasicConstraints requires the Acmebot identity to have the Key Vault Crypto User role (or keys/sign permission) on the vault.", ex);
        }
    }

    private static async Task<KeyVaultCertificateWithPolicy?> GetSigningCertificateAsync(CertificateClient certificateClient, string certificateName, CancellationToken cancellationToken)
    {
        KeyVaultCertificateWithPolicy certificate;

        try
        {
            certificate = (await certificateClient.GetCertificateAsync(certificateName, cancellationToken)).Value;
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == (int)HttpStatusCode.NotFound)
        {
            return null;
        }

        // Key Vault refuses key operations on a disabled or expired certificate version
        var now = DateTimeOffset.UtcNow;
        var properties = certificate.Properties;

        var isUsable = certificate.Cer is { Length: > 0 } &&
                       certificate.KeyId is not null &&
                       properties.Enabled != false &&
                       properties.NotBefore.GetValueOrDefault(DateTimeOffset.MinValue) <= now &&
                       properties.ExpiresOn.GetValueOrDefault(DateTimeOffset.MinValue) > now;

        return isUsable ? certificate : null;
    }

    private static async Task<KeyVaultCertificateWithPolicy> CreateSelfSignedCertificateAsync(CertificateClient certificateClient, CertificatePolicyItem certificatePolicyItem, Uri endpoint, ILogger logger, CancellationToken cancellationToken)
    {
        LogCreatingSelfSignedCertificate(logger, certificatePolicyItem.CertificateName);

        // An in-progress pending operation blocks creating a new version
        await DeletePendingCertificateOperationAsync(certificateClient, certificatePolicyItem.CertificateName, cancellationToken);

        // The self-signed version only holds the new key until the issued certificate is merged. If issuance fails after this
        // point, renewal evaluation recognises it as a key holder and retries it (see CertificateActivities.EvaluateCertificateState).
        var certificatePolicy = certificatePolicyItem.ToCertificatePolicy(issuerName: WellKnownIssuerNames.Self, reuseKey: false);

        certificatePolicy.ValidityInMonths = 1;

        var certificateOperation = await certificateClient.StartCreateCertificateAsync(
            certificatePolicyItem.CertificateName,
            certificatePolicy,
            tags: certificatePolicyItem.ToCertificateTags(endpoint),
            cancellationToken: cancellationToken);

        return (await certificateOperation.WaitForCompletionAsync(cancellationToken)).Value;
    }

    private static async Task<CertificateOperation> StartReuseKeyCertificateOperationAsync(CertificateClient certificateClient, CertificatePolicyItem certificatePolicyItem, Uri endpoint, PublicKey signingPublicKey, ILogger logger, CancellationToken cancellationToken)
    {
        var certificateName = certificatePolicyItem.CertificateName;
        var certificatePolicy = certificatePolicyItem.ToCertificatePolicy(reuseKey: true);
        var tags = certificatePolicyItem.ToCertificateTags(endpoint);

        CertificateOperation certificateOperation;

        try
        {
            certificateOperation = await certificateClient.StartCreateCertificateAsync(certificateName, certificatePolicy, tags: tags, preserveCertificateOrder: true, cancellationToken: cancellationToken);
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == (int)HttpStatusCode.Conflict)
        {
            // Never reuse the conflicting operation: it can hold another key, or older DNS names and tags, or have finished in the
            // meantime. The key is reused either way, so starting over costs nothing.
            if (!await DeletePendingCertificateOperationAsync(certificateClient, certificateName, cancellationToken))
            {
                // The conflict is not caused by a pending operation, for example a soft-deleted certificate
                throw;
            }

            LogReplacingPendingCertificateOperation(logger, certificateName);

            certificateOperation = await certificateClient.StartCreateCertificateAsync(certificateName, certificatePolicy, tags: tags, preserveCertificateOrder: true, cancellationToken: cancellationToken);
        }

        if (!KeyVaultCsrSigner.HasSamePublicKey(KeyVaultCsrSigner.GetPublicKey(certificateOperation.Properties.Csr), signingPublicKey))
        {
            throw new InvalidOperationException("Key Vault did not reuse the current key for the new certificate version. Changing the key type, size, or curve of an existing certificate is not supported while ExcludeCsrBasicConstraints is enabled.");
        }

        return certificateOperation;
    }

    // Returns false when there is no pending operation
    private static async Task<bool> DeletePendingCertificateOperationAsync(CertificateClient certificateClient, string certificateName, CancellationToken cancellationToken)
    {
        CertificateOperation certificateOperation;

        try
        {
            certificateOperation = await certificateClient.GetCertificateOperationAsync(certificateName, cancellationToken);
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == (int)HttpStatusCode.NotFound)
        {
            return false;
        }

        // Only an in-progress pending object blocks a new version (409); Key Vault overwrites completed, failed or cancelled ones on create.
        // HasCompleted cannot tell them apart here, because only UpdateStatus sets it and a lookup does not call it.
        if (string.Equals(certificateOperation.Properties.Status, "inProgress", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                await certificateOperation.DeleteAsync(cancellationToken);
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == (int)HttpStatusCode.NotFound)
            {
                // Already removed by a concurrent run
            }
        }

        return true;
    }

    [LoggerMessage(LogLevel.Information, "No usable Key Vault certificate version to sign the CSR with. Creating a self-signed version to hold a new key. CertificateName: {CertificateName}")]
    private static partial void LogCreatingSelfSignedCertificate(ILogger logger, string certificateName);

    [LoggerMessage(LogLevel.Warning, "Replacing a pending Key Vault certificate operation left by an earlier or concurrent attempt. CertificateName: {CertificateName}")]
    private static partial void LogReplacingPendingCertificateOperation(ILogger logger, string certificateName);

    [LoggerMessage(LogLevel.Error, "ACME domain validation failed. ProblemDetails: {ProblemDetailsJson}")]
    private static partial void LogAcmeDomainValidationError(ILogger logger, string problemDetailsJson);

    [LoggerMessage(LogLevel.Warning, "ACME order replacement was already consumed by another order. Retrying without ARI replaces hint. CertificateId: {CertificateId}")]
    private static partial void LogAlreadyReplacedRetry(ILogger logger, string certificateId);

    internal static Exception CreateOrderInvalidException(IReadOnlyList<AcmeProblemDetails> problems)
    {
        if (problems.Count == 0)
        {
            return new InvalidOperationException("ACME validation failed and the order is now invalid, but the certificate authority did not report a problem for the order or any of its challenges. Review the order on the certificate authority and retry the operation.");
        }

        if (problems.All(x => x.Type is { } type && type == AcmeProblemTypes.Dns))
        {
            return new RetriableOrchestratorException("ACME validation failed because of a DNS-related error. The operation will be retried automatically.");
        }

        return new InvalidOperationException($"ACME validation failed and the order is now invalid. Review the reported problem and retry the operation.\nLast problem: {JsonSerializer.Serialize(problems[^1])}");
    }

    internal static async Task<OrderDetails> CreateOrderAsync(AcmeClientContext acmeContext, IReadOnlyList<string> dnsNames, string? profile, string? replaces, ILogger logger)
    {
        var identifiers = dnsNames.Select(x => new AcmeIdentifier
        {
            Type = AcmeIdentifierTypes.Dns,
            Value = x
        }).ToArray();

        try
        {
            var result = await acmeContext.Client.CreateOrderAsync(
                acmeContext.Account,
                identifiers,
                profile: profile,
                replaces: replaces);

            return OrderDetails.FromResult(result);
        }
        catch (AcmeProtocolException ex) when (!string.IsNullOrEmpty(replaces) && ex.IsAlreadyReplaced)
        {
            LogAlreadyReplacedRetry(logger, replaces);

            var result = await acmeContext.Client.CreateOrderAsync(
                acmeContext.Account,
                identifiers,
                profile: profile,
                replaces: null);

            return OrderDetails.FromResult(result);
        }
    }

    private static string? NormalizeProfile(string? profile) => string.IsNullOrWhiteSpace(profile) ? null : profile.Trim();
}

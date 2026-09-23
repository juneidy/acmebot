using System.Security.Cryptography;

using Acmebot.App.Extensions;
using Acmebot.App.Functions.Orchestration;
using Acmebot.App.Models;

using Azure.Security.KeyVault.Certificates;

using Xunit;

namespace Acmebot.App.Tests;

public sealed class CertificateActivitiesTests
{
    private static readonly Uri s_endpoint = new("https://acme.example.com/directory");

    [Fact]
    public void EvaluateCertificateState_WithKeyHolder_RenewsImmediately()
    {
        var now = DateTimeOffset.UtcNow;
        var certificate = CreateKeyHolder(now.AddDays(-2), now.AddDays(28));

        var evaluation = CertificateActivities.EvaluateCertificateState(certificate, s_endpoint, now);

        Assert.NotNull(evaluation);
        Assert.True(evaluation.IsActive);
        Assert.True(evaluation.ShouldRenew);
        Assert.Contains("key holder", evaluation.Reason);
    }

    [Fact]
    public void EvaluateCertificateState_WithRecentKeyHolder_WaitsForRunningIssuance()
    {
        var now = DateTimeOffset.UtcNow;
        var createdOn = now.AddMinutes(-10);
        var certificate = CreateKeyHolder(createdOn, now.AddDays(30));

        var evaluation = CertificateActivities.EvaluateCertificateState(certificate, s_endpoint, now);

        Assert.NotNull(evaluation);
        Assert.True(evaluation.IsActive);
        Assert.False(evaluation.ShouldRenew);
        Assert.Equal(createdOn.AddHours(1), evaluation.NextCheck);
    }

    [Theory]
    [InlineData(59, false)]
    [InlineData(60, true)]
    public void EvaluateCertificateState_WithKeyHolderAtGracePeriodBoundary_RenewsOnlyAfterOneHour(int minutesSinceCreated, bool shouldRenew)
    {
        var now = new DateTimeOffset(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);
        var certificate = CreateKeyHolder(now.AddMinutes(-minutesSinceCreated), now.AddDays(30));

        var evaluation = CertificateActivities.EvaluateCertificateState(certificate, s_endpoint, now);

        Assert.NotNull(evaluation);
        Assert.Equal(shouldRenew, evaluation.ShouldRenew);
    }

    [Fact]
    public void EvaluateCertificateState_WithExpiredKeyHolder_RenewsImmediately()
    {
        var now = DateTimeOffset.UtcNow;
        var certificate = CreateKeyHolder(now.AddDays(-40), now.AddDays(-10));

        var evaluation = CertificateActivities.EvaluateCertificateState(certificate, s_endpoint, now);

        Assert.NotNull(evaluation);
        Assert.True(evaluation.ShouldRenew);
        Assert.Contains("key holder", evaluation.Reason);
    }

    [Fact]
    public void EvaluateCertificateState_WithDisabledKeyHolder_IsInactive()
    {
        var now = DateTimeOffset.UtcNow;
        var certificate = CreateKeyHolder(now.AddDays(-2), now.AddDays(28), enabled: false);

        var evaluation = CertificateActivities.EvaluateCertificateState(certificate, s_endpoint, now);

        Assert.NotNull(evaluation);
        Assert.False(evaluation.IsActive);
        Assert.False(evaluation.ShouldRenew);
    }

    [Fact]
    public void EvaluateCertificateState_WithKeyHolderFromOtherEndpoint_IsInactive()
    {
        var now = DateTimeOffset.UtcNow;
        var certificate = CreateKeyHolder(now.AddDays(-2), now.AddDays(28));

        var evaluation = CertificateActivities.EvaluateCertificateState(certificate, new Uri("https://other.example.com/directory"), now);

        Assert.NotNull(evaluation);
        Assert.False(evaluation.IsActive);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void EvaluateCertificateState_WithIssuedCertificate_DefersToRenewalSchedule(bool withCertificateId)
    {
        var now = DateTimeOffset.UtcNow;
        var certificate = CreateIssuedCertificate(now.AddDays(-2), now.AddDays(43), withCertificateId);

        Assert.Null(CertificateActivities.EvaluateCertificateState(certificate, s_endpoint, now));
    }

    [Fact]
    public void EvaluateCertificateState_WithExpiredIssuedCertificate_RenewsImmediately()
    {
        var now = DateTimeOffset.UtcNow;
        var certificate = CreateIssuedCertificate(now.AddDays(-50), now.AddDays(-5), withCertificateId: true);

        var evaluation = CertificateActivities.EvaluateCertificateState(certificate, s_endpoint, now);

        Assert.NotNull(evaluation);
        Assert.True(evaluation.ShouldRenew);
        Assert.Contains("expired", evaluation.Reason);
    }

    private static KeyVaultCertificate CreateKeyHolder(DateTimeOffset createdOn, DateTimeOffset expiresOn, bool enabled = true)
    {
        using var key = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient("example-com");
        var version = certificateClient.CreateVersion(key, createdOn.AddMinutes(-5), expiresOn, CreateTags(withCertificateId: false));

        return certificateClient.ToKeyVaultCertificate(version with { CreatedOn = createdOn, Enabled = enabled });
    }

    private static KeyVaultCertificate CreateIssuedCertificate(DateTimeOffset notBefore, DateTimeOffset expiresOn, bool withCertificateId)
    {
        using var key = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient("example-com");
        var cer = TestCertificates.CreateIssuedCertificate(key, notBefore, expiresOn);
        var version = certificateClient.CreateVersion(key, notBefore, expiresOn, CreateTags(withCertificateId), cer);

        return certificateClient.ToKeyVaultCertificate(version with { CreatedOn = notBefore });
    }

    private static Dictionary<string, string> CreateTags(bool withCertificateId)
    {
        var policyItem = new CertificatePolicyItem
        {
            CertificateName = "example-com",
            DnsNames = ["example.com"],
            DnsProviderName = "Test DNS",
            KeyType = "RSA",
            KeySize = 2048
        };

        var tags = policyItem.ToCertificateTags(s_endpoint);

        if (withCertificateId)
        {
            tags.SetCertificateId("aki.serial");
        }

        return new Dictionary<string, string>(tags);
    }
}

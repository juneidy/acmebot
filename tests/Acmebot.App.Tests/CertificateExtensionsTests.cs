using System.Security.Cryptography;
using System.Text.Json;

using Acmebot.App.Extensions;
using Acmebot.App.Models;

using Azure.Security.KeyVault.Certificates;

using Xunit;

namespace Acmebot.App.Tests;

public sealed class CertificateExtensionsTests
{
    private static readonly Uri s_endpoint = new("https://acme-v02.api.letsencrypt.org/directory");

    [Fact]
    public void IsIssuedByAcmebot_WithMetadataTag_ReturnsTrue()
    {
        var properties = CreateCertificateProperties(("Acmebot", """{"endpoint":"acme-v02.api.letsencrypt.org"}"""));

        Assert.True(properties.IsIssuedByAcmebot());
    }

    [Fact]
    public void IsIssuedByAcmebot_WithLegacyIssuerTag_ReturnsTrue()
    {
        var properties = CreateCertificateProperties(("Issuer", "Acmebot"));

        Assert.True(properties.IsIssuedByAcmebot());
    }

    [Fact]
    public void IsIssuedByAcmebot_WithNonAcmebotLegacyIssuerTag_ReturnsFalse()
    {
        var properties = CreateCertificateProperties(("Issuer", "Other"));

        Assert.False(properties.IsIssuedByAcmebot());
    }

    [Theory]
    [InlineData("""{"endpoint":"acme-v02.api.letsencrypt.org"}""")]
    [InlineData("""{"endpoint":"https://acme-v02.api.letsencrypt.org/directory"}""")]
    public void IsSameEndpoint_WithMetadataEndpoint_ReturnsTrue(string metadata)
    {
        var properties = CreateCertificateProperties(("Acmebot", metadata));

        Assert.True(properties.IsSameEndpoint(s_endpoint));
    }

    [Fact]
    public void IsSameEndpoint_WithInvalidMetadataJson_FallsBackToLegacyEndpointTag()
    {
        var properties = CreateCertificateProperties(
            ("Acmebot", "{"),
            ("Issuer", "Acmebot"),
            ("Endpoint", "https://acme-v02.api.letsencrypt.org/directory"));

        Assert.True(properties.IsSameEndpoint(s_endpoint));
    }

    [Fact]
    public void TryGetCertificateId_WithCertificateIdInMetadata_ReturnsTrue()
    {
        var properties = CreateCertificateProperties(("Acmebot", """{"certificateId":"abc123"}"""));

        var result = properties.TryGetCertificateId(out var certificateId);

        Assert.True(result);
        Assert.Equal("abc123", certificateId);
    }

    [Fact]
    public void SetCertificateId_WithExistingMetadata_PreservesEndpointAndDnsProvider()
    {
        var tags = new Dictionary<string, string>
        {
            ["Acmebot"] = """{"endpoint":"acme-v02.api.letsencrypt.org","dnsProvider":"Azure DNS"}"""
        };

        tags.SetCertificateId("cert-id");

        var properties = CreateCertificateProperties(tags.Select(x => (x.Key, x.Value)).ToArray());

        Assert.True(properties.TryGetCertificateId(out var certificateId));
        Assert.Equal("cert-id", certificateId);
        Assert.True(properties.IsSameEndpoint(s_endpoint));
    }

    [Fact]
    public void ToCertificateTags_TrimsCustomTagsAndSkipsReservedAcmebotTag()
    {
        var policy = CreatePolicy(profile: null);
        policy.Tags = new Dictionary<string, string>
        {
            [" environment "] = " production ",
            ["Acmebot"] = "user supplied"
        };

        var tags = policy.ToCertificateTags(s_endpoint);

        Assert.Equal("production", tags["environment"]);
        Assert.Contains("Acmebot", tags.Keys);
        Assert.DoesNotContain("user supplied", tags.Values);
    }

    [Fact]
    public void ToCertificateTags_WithProfile_StoresProfileInMetadata()
    {
        var policy = CreatePolicy(profile: " tlsserver ");

        var tags = policy.ToCertificateTags(s_endpoint);

        using var metadata = JsonDocument.Parse(tags["Acmebot"]);
        Assert.Equal("tlsserver", metadata.RootElement.GetProperty("profile").GetString());
    }

    [Fact]
    public void ToCertificateTags_WithoutProfile_OmitsProfileFromMetadata()
    {
        var policy = CreatePolicy(profile: null);

        var tags = policy.ToCertificateTags(s_endpoint);

        using var metadata = JsonDocument.Parse(tags["Acmebot"]);
        Assert.False(metadata.RootElement.TryGetProperty("profile", out _));
    }

    [Fact]
    public void ToCertificatePolicyItem_WithProfileMetadata_RestoresProfile()
    {
        var tags = CreatePolicy(profile: "tlsserver").ToCertificateTags(s_endpoint);
        var certificate = CreateCertificate(tags);

        var policy = certificate.ToCertificatePolicyItem();

        Assert.Equal("tlsserver", policy.Profile);
    }

    [Fact]
    public void SetCertificateId_PreservesProfileMetadata()
    {
        var tags = CreatePolicy(profile: "tlsserver").ToCertificateTags(s_endpoint);

        tags.SetCertificateId("certificate-id");

        using var metadata = JsonDocument.Parse(tags["Acmebot"]);
        Assert.Equal("tlsserver", metadata.RootElement.GetProperty("profile").GetString());
        Assert.Equal("certificate-id", metadata.RootElement.GetProperty("certificateId").GetString());
    }

    [Fact]
    public void IsSelfSignedKeyHolder_WithSelfSignedManagedVersionWithoutCertificateId_ReturnsTrue()
    {
        Assert.True(CreateKeyVaultCertificate(selfSigned: true, ("Acmebot", """{"endpoint":"acme-v02.api.letsencrypt.org"}""")).IsSelfSignedKeyHolder());
    }

    [Fact]
    public void IsSelfSignedKeyHolder_WithCertificateId_ReturnsFalse()
    {
        Assert.False(CreateKeyVaultCertificate(selfSigned: true, ("Acmebot", """{"endpoint":"acme-v02.api.letsencrypt.org","certificateId":"aki.serial"}""")).IsSelfSignedKeyHolder());
    }

    [Fact]
    public void IsSelfSignedKeyHolder_WithIssuedCertificate_ReturnsFalse()
    {
        Assert.False(CreateKeyVaultCertificate(selfSigned: false, ("Acmebot", """{"endpoint":"acme-v02.api.letsencrypt.org"}""")).IsSelfSignedKeyHolder());
    }

    [Fact]
    public void IsSelfSignedKeyHolder_WithoutAcmebotTag_ReturnsFalse()
    {
        Assert.False(CreateKeyVaultCertificate(selfSigned: true).IsSelfSignedKeyHolder());
    }

    [Fact]
    public void IsSelfSignedKeyHolder_WithoutCer_ReturnsFalse()
    {
        using var key = RSA.Create(2048);
        var certificateClient = new FakeCertificateClient("example-com");
        var tags = new Dictionary<string, string> { ["Acmebot"] = """{"endpoint":"acme-v02.api.letsencrypt.org"}""" };
        var version = certificateClient.CreateVersion(key, tags: tags) with { Cer = null };

        Assert.False(certificateClient.ToKeyVaultCertificate(version).IsSelfSignedKeyHolder());
    }

    private static KeyVaultCertificate CreateKeyVaultCertificate(bool selfSigned, params (string Key, string Value)[] tags)
    {
        using var key = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var certificateClient = new FakeCertificateClient("example-com");
        var cer = selfSigned
            ? TestCertificates.CreateSelfSignedCertificate(key, now.AddDays(-1), now.AddDays(30))
            : TestCertificates.CreateIssuedCertificate(key, now.AddDays(-1), now.AddDays(30));
        var version = certificateClient.CreateVersion(key, tags: tags.ToDictionary(x => x.Key, x => x.Value), cer: cer);

        return certificateClient.ToKeyVaultCertificate(version);
    }

    private static CertificatePolicyItem CreatePolicy(string? profile)
    {
        return new CertificatePolicyItem
        {
            CertificateName = "example-com",
            DnsNames = ["example.com"],
            DnsProviderName = "Azure DNS",
            KeyType = "RSA",
            KeySize = 2048,
            Profile = profile
        };
    }

    private static KeyVaultCertificateWithPolicy CreateCertificate(IDictionary<string, string> tags)
    {
        var subjectAlternativeNames = new SubjectAlternativeNames();
        subjectAlternativeNames.DnsNames.Add("example.com");

        var policy = new CertificatePolicy(WellKnownIssuerNames.Unknown, "CN=example.com", subjectAlternativeNames)
        {
            KeyType = CertificateKeyType.Rsa,
            KeySize = 2048
        };

        var properties = new CertificateProperties("example-com");

        foreach (var tag in tags)
        {
            properties.Tags[tag.Key] = tag.Value;
        }

        return CertificateModelFactory.KeyVaultCertificateWithPolicy(
            properties,
            new Uri("https://vault.example/keys/example-com/version"),
            new Uri("https://vault.example/secrets/example-com/version"),
            [],
            policy);
    }

    private static CertificateProperties CreateCertificateProperties(params (string Key, string Value)[] tags)
    {
        var properties = new CertificateProperties("example-com");

        foreach (var (key, value) in tags)
        {
            properties.Tags[key] = value;
        }

        return properties;
    }
}

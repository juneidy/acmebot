using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Acmebot.App.Tests;

internal static class TestCertificates
{
    public static readonly string[] DefaultDnsNames = ["example.com", "www.example.com"];

    public static AsymmetricAlgorithm CreateKey(string keyType) => keyType switch
    {
        "RSA-2048" => RSA.Create(2048),
        "EC-P256" => ECDsa.Create(ECCurve.NamedCurves.nistP256),
        "EC-P384" => ECDsa.Create(ECCurve.NamedCurves.nistP384),
        "EC-P521" => ECDsa.Create(ECCurve.NamedCurves.nistP521),
        _ => throw new ArgumentOutOfRangeException(nameof(keyType))
    };

    // Mirrors the extensions Key Vault puts in the CSRs it generates
    public static byte[] CreateKeyVaultStyleCsr(AsymmetricAlgorithm key, IReadOnlyList<string>? dnsNames = null)
    {
        dnsNames = dnsNames is { Count: > 0 } ? dnsNames : DefaultDnsNames;

        var request = CreateRequest($"CN={dnsNames[0]}", key);
        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();

        foreach (var dnsName in dnsNames)
        {
            subjectAlternativeNames.AddDnsName(dnsName);
        }

        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));
        request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

        return request.CreateSigningRequest();
    }

    public static byte[] CreateSelfSignedCertificate(AsymmetricAlgorithm key, DateTimeOffset notBefore, DateTimeOffset notAfter, string subjectName = "CN=example.com")
    {
        using var certificate = CreateRequest(subjectName, key).CreateSelfSigned(notBefore, notAfter);

        return certificate.RawData;
    }

    private static CertificateRequest CreateRequest(string subjectName, AsymmetricAlgorithm key) => key switch
    {
        RSA rsa => new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
        ECDsa ecdsa => new CertificateRequest(subjectName, ecdsa, HashAlgorithmName.SHA256),
        _ => throw new NotSupportedException()
    };
}

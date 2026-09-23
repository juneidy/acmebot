using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Acmebot.App.Acme;

using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

using Xunit;

namespace Acmebot.App.Tests;

public sealed class KeyVaultCsrSignerTests
{
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string KeyUsageOid = "2.5.29.15";

    [Theory]
    [InlineData("RSA-2048")]
    [InlineData("EC-P256")]
    [InlineData("EC-P384")]
    [InlineData("EC-P521")]
    public void RebuildWithoutBasicConstraints_RemovesOnlyBasicConstraints(string keyType)
    {
        using var key = CreateKey(keyType);
        var templateCsr = CreateKeyVaultStyleCsr(key);

        var csr = KeyVaultCsrSigner.RebuildWithoutBasicConstraints(templateCsr, new FakeCryptographyClient(key));

        // Loading validates the self-signature of each CSR
        var template = Load(templateCsr);
        var rebuilt = Load(csr);

        Assert.Equal(template.SubjectName.Name, rebuilt.SubjectName.Name);
        Assert.True(KeyVaultCsrSigner.HasSamePublicKey(template.PublicKey, rebuilt.PublicKey));
        Assert.DoesNotContain(rebuilt.CertificateExtensions, x => x.Oid?.Value == BasicConstraintsOid);

        var expectedExtensions = template.CertificateExtensions.Where(x => x.Oid?.Value != BasicConstraintsOid).ToArray();

        Assert.Equal(expectedExtensions.Length, rebuilt.CertificateExtensions.Count);

        foreach (var expected in expectedExtensions)
        {
            var actual = Assert.Single(rebuilt.CertificateExtensions, x => x.Oid?.Value == expected.Oid?.Value);

            Assert.Equal(expected.Critical, actual.Critical);
            Assert.Equal(expected.RawData, actual.RawData);
        }

        Assert.True(Assert.Single(rebuilt.CertificateExtensions, x => x.Oid?.Value == KeyUsageOid).Critical);
    }

    [Theory]
    [InlineData("RSA-2048", "RS256")]
    [InlineData("EC-P256", "ES256")]
    [InlineData("EC-P384", "ES384")]
    [InlineData("EC-P521", "ES512")]
    public void RebuildWithoutBasicConstraints_UsesKeyVaultAlgorithmForKey(string keyType, string expectedAlgorithm)
    {
        using var key = CreateKey(keyType);
        var signer = new FakeCryptographyClient(key);

        KeyVaultCsrSigner.RebuildWithoutBasicConstraints(CreateKeyVaultStyleCsr(key), signer);

        Assert.Equal(expectedAlgorithm, Assert.Single(signer.Algorithms).ToString());
    }

    [Fact]
    public void RebuildWithoutBasicConstraints_WithDifferentSigningKey_Throws()
    {
        using var templateKey = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);

        var templateCsr = CreateKeyVaultStyleCsr(templateKey);

        Assert.ThrowsAny<CryptographicException>(() => KeyVaultCsrSigner.RebuildWithoutBasicConstraints(templateCsr, new FakeCryptographyClient(otherKey)));
    }

    [Fact]
    public void HasSamePublicKey_WithDifferentKeys_ReturnsFalse()
    {
        using var key1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var key2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        Assert.True(KeyVaultCsrSigner.HasSamePublicKey(new PublicKey(key1), new PublicKey(key1)));
        Assert.False(KeyVaultCsrSigner.HasSamePublicKey(new PublicKey(key1), new PublicKey(key2)));
    }

    [Fact]
    public void ConvertIeeeP1363ToDer_EncodesMinimalIntegers()
    {
        byte[] r = [0x00, 0x00, 0x7F, .. Enumerable.Repeat((byte)0x11, 29)];
        byte[] s = [0x80, .. Enumerable.Repeat((byte)0x22, 31)];

        var der = KeyVaultCsrSigner.ConvertIeeeP1363ToDer([.. r, .. s]);

        // DER mode rejects integers that are not minimally encoded
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();

        Assert.Equal(new BigInteger(r, isUnsigned: true, isBigEndian: true), sequence.ReadInteger());
        Assert.Equal(new BigInteger(s, isUnsigned: true, isBigEndian: true), sequence.ReadInteger());
        Assert.False(sequence.HasData);
        Assert.False(reader.HasData);
    }

    [Fact]
    public void ConvertIeeeP1363ToDer_ProducesVerifiableSignatures()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        // Enough signatures that some r or s values start with a zero byte
        for (var i = 0; i < 256; i++)
        {
            var hash = SHA256.HashData(BitConverter.GetBytes(i));
            var der = KeyVaultCsrSigner.ConvertIeeeP1363ToDer(key.SignHash(hash));

            Assert.True(key.VerifyHash(hash, der, DSASignatureFormat.Rfc3279DerSequence));
        }
    }

    private static AsymmetricAlgorithm CreateKey(string keyType) => keyType switch
    {
        "RSA-2048" => RSA.Create(2048),
        "EC-P256" => ECDsa.Create(ECCurve.NamedCurves.nistP256),
        "EC-P384" => ECDsa.Create(ECCurve.NamedCurves.nistP384),
        "EC-P521" => ECDsa.Create(ECCurve.NamedCurves.nistP521),
        _ => throw new ArgumentOutOfRangeException(nameof(keyType))
    };

    // Mirrors the extensions Key Vault puts in the CSRs it generates
    private static byte[] CreateKeyVaultStyleCsr(AsymmetricAlgorithm key)
    {
        var request = key switch
        {
            RSA rsa => new CertificateRequest("CN=example.com", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => new CertificateRequest("CN=example.com", ecdsa, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException()
        };

        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();

        subjectAlternativeNames.AddDnsName("example.com");
        subjectAlternativeNames.AddDnsName("www.example.com");

        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: false));
        request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

        return request.CreateSigningRequest();
    }

    private static CertificateRequest Load(byte[] csr) => CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

    // Signs locally the way Key Vault does: PKCS#1 v1.5 for RSA, IEEE P1363 (r || s) for ECDSA
    private sealed class FakeCryptographyClient(AsymmetricAlgorithm key) : CryptographyClient
    {
        public List<SignatureAlgorithm> Algorithms { get; } = [];

        public override SignResult Sign(SignatureAlgorithm algorithm, byte[] digest, CancellationToken cancellationToken = default)
        {
            Algorithms.Add(algorithm);

            var signature = key switch
            {
                RSA rsa => rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                ECDsa ecdsa => ecdsa.SignHash(digest),
                _ => throw new NotSupportedException()
            };

            return CryptographyModelFactory.SignResult("https://example.vault.azure.net/keys/test/1", signature, algorithm);
        }
    }
}

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Azure.Security.KeyVault.Keys.Cryptography;

namespace Acmebot.App.Acme;

// Rebuilds a Key Vault CSR without the Basic Constraints extension, which some CAs (such as AWS ACM) reject.
// The new CSR is signed through the Key Vault Keys API, so only a digest leaves the application and the private key stays in Key Vault.
internal static class KeyVaultCsrSigner
{
    private const string BasicConstraintsOid = "2.5.29.19";

    public static byte[] RebuildWithoutBasicConstraints(byte[] templateCsr, CryptographyClient signer)
    {
        var template = CertificateRequest.LoadSigningRequest(templateCsr, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var publicKey = template.PublicKey;

        using var rsa = publicKey.GetRSAPublicKey();
        using var ecdsa = rsa is null ? publicKey.GetECDsaPublicKey() : null;

        KeyVaultSignatureGenerator generator;

        if (rsa is not null)
        {
            generator = new KeyVaultSignatureGenerator(publicKey, X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1), signer, SignatureAlgorithm.RS256, HashAlgorithmName.SHA256, isEcdsa: false);
        }
        else if (ecdsa is not null)
        {
            var (signatureAlgorithm, digestAlgorithm) = GetEcdsaAlgorithms(publicKey);

            generator = new KeyVaultSignatureGenerator(publicKey, X509SignatureGenerator.CreateForECDsa(ecdsa), signer, signatureAlgorithm, digestAlgorithm, isEcdsa: true);
        }
        else
        {
            throw new NotSupportedException($"The CSR public key algorithm '{publicKey.Oid.Value}' is not supported.");
        }

        var request = new CertificateRequest(template.SubjectName, publicKey, generator.DigestAlgorithm, rsa is not null ? RSASignaturePadding.Pkcs1 : null);

        // Copying the extension instances keeps each one's critical flag
        foreach (var extension in template.CertificateExtensions)
        {
            if (extension.Oid?.Value != BasicConstraintsOid)
            {
                request.CertificateExtensions.Add(extension);
            }
        }

        var csr = request.CreateSigningRequest(generator);

        // LoadSigningRequest validates the self-signature, so a key mismatch fails here instead of as badCSR from the CA
        CertificateRequest.LoadSigningRequest(csr, generator.DigestAlgorithm);

        return csr;
    }

    public static PublicKey GetPublicKey(byte[] csr) => CertificateRequest.LoadSigningRequest(csr, HashAlgorithmName.SHA256).PublicKey;

    public static bool HasSamePublicKey(PublicKey x, PublicKey y) => x.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(y.ExportSubjectPublicKeyInfo());

    // Key Vault returns ECDSA signatures as r || s (IEEE P1363), but X.509 expects a DER SEQUENCE { r INTEGER, s INTEGER }
    internal static byte[] ConvertIeeeP1363ToDer(ReadOnlySpan<byte> signature)
    {
        var half = signature.Length / 2;
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            WriteUnsignedInteger(writer, signature[..half]);
            WriteUnsignedInteger(writer, signature[half..]);
        }

        return writer.Encode();

        static void WriteUnsignedInteger(AsnWriter writer, ReadOnlySpan<byte> value)
        {
            // DER integers must use the minimum number of bytes, and r or s can start with zero bytes
            var trimmed = value.TrimStart((byte)0);

            if (trimmed.IsEmpty)
            {
                writer.WriteInteger(0);
            }
            else
            {
                writer.WriteIntegerUnsigned(trimmed);
            }
        }
    }

    private static (SignatureAlgorithm, HashAlgorithmName) GetEcdsaAlgorithms(PublicKey publicKey)
    {
        var curveParameters = publicKey.EncodedParameters?.RawData ?? throw new NotSupportedException("The CSR elliptic curve public key does not specify a named curve.");
        var curveOid = AsnDecoder.ReadObjectIdentifier(curveParameters, AsnEncodingRules.DER, out _);

        return curveOid switch
        {
            "1.2.840.10045.3.1.7" => (SignatureAlgorithm.ES256, HashAlgorithmName.SHA256),
            "1.3.132.0.34" => (SignatureAlgorithm.ES384, HashAlgorithmName.SHA384),
            "1.3.132.0.35" => (SignatureAlgorithm.ES512, HashAlgorithmName.SHA512),
            "1.3.132.0.10" => (SignatureAlgorithm.ES256K, HashAlgorithmName.SHA256),
            _ => throw new NotSupportedException($"The CSR elliptic curve '{curveOid}' is not supported.")
        };
    }

    private sealed class KeyVaultSignatureGenerator(
        PublicKey publicKey,
        X509SignatureGenerator algorithmIdentifierSource,
        CryptographyClient signer,
        SignatureAlgorithm signatureAlgorithm,
        HashAlgorithmName digestAlgorithm,
        bool isEcdsa) : X509SignatureGenerator
    {
        public HashAlgorithmName DigestAlgorithm => digestAlgorithm;

        protected override PublicKey BuildPublicKey() => publicKey;

        // The built-in generator only encodes the algorithm identifier here, which does not need the private key
        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) => algorithmIdentifierSource.GetSignatureAlgorithmIdentifier(hashAlgorithm);

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            if (hashAlgorithm != digestAlgorithm)
            {
                throw new CryptographicException($"The hash algorithm '{hashAlgorithm.Name}' does not match the Key Vault signature algorithm '{signatureAlgorithm}'.");
            }

            var digest = CryptographicOperations.HashData(hashAlgorithm, data);
            var signature = signer.Sign(signatureAlgorithm, digest).Signature;

            return isEcdsa ? ConvertIeeeP1363ToDer(signature) : signature;
        }
    }
}

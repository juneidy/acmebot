using System.Security.Cryptography;

using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace Acmebot.App.Tests;

// Signs locally the way Key Vault does: PKCS#1 v1.5 for RSA, IEEE P1363 (r || s) for ECDSA
internal sealed class FakeCryptographyClient(AsymmetricAlgorithm key, Exception? signException = null) : CryptographyClient
{
    public List<SignatureAlgorithm> Algorithms { get; } = [];

    public override SignResult Sign(SignatureAlgorithm algorithm, byte[] digest, CancellationToken cancellationToken = default)
    {
        Algorithms.Add(algorithm);

        if (signException is not null)
        {
            throw signException;
        }

        var signature = key switch
        {
            RSA rsa => rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            ECDsa ecdsa => ecdsa.SignHash(digest),
            _ => throw new NotSupportedException()
        };

        return CryptographyModelFactory.SignResult("https://example.vault.azure.net/keys/test/1", signature, algorithm);
    }
}

using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Klassd.Auth.Core.Sessions;

/// <summary>
/// Supplies the credentials used to sign access-token JWTs and the keys used to validate them.
/// Lets the signing algorithm be swapped (HS256 by default, RS256 via UseRsaSigning) without
/// touching <see cref="SessionService"/>.
/// </summary>
public interface ITokenSigningKey
{
    SigningCredentials SigningCredentials { get; }
    IReadOnlyList<SecurityKey> ValidationKeys { get; }

    /// <summary>Public keys for a JWKS endpoint. Empty for symmetric keys (the secret must not be published).</summary>
    IReadOnlyList<JsonWebKey> PublicJwks { get; }
}

/// <summary>HMAC-SHA256 signing from a shared secret. Fine for first-party apps; no public JWKS.</summary>
public sealed class SymmetricTokenSigningKey : ITokenSigningKey
{
    public SymmetricTokenSigningKey(SessionConfig config)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.SigningKey));
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        ValidationKeys = [key];
    }

    public SigningCredentials SigningCredentials { get; }
    public IReadOnlyList<SecurityKey> ValidationKeys { get; }
    public IReadOnlyList<JsonWebKey> PublicJwks => [];
}

/// <summary>
/// RSA-SHA256 signing. Issues with the private key; publishes the public key as a JWK so resource
/// servers can validate tokens via a JWKS endpoint without sharing a secret.
/// </summary>
public sealed class RsaTokenSigningKey : ITokenSigningKey
{
    public RsaTokenSigningKey(RSA rsa, string keyId)
    {
        var privateKey = new RsaSecurityKey(rsa) { KeyId = keyId };
        SigningCredentials = new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256);
        ValidationKeys = [privateKey];

        var publicJwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(
            new RsaSecurityKey(rsa.ExportParameters(false)) { KeyId = keyId });
        publicJwk.Use = "sig";
        publicJwk.Alg = SecurityAlgorithms.RsaSha256;
        PublicJwks = [publicJwk];
    }

    public SigningCredentials SigningCredentials { get; }
    public IReadOnlyList<SecurityKey> ValidationKeys { get; }
    public IReadOnlyList<JsonWebKey> PublicJwks { get; }
}

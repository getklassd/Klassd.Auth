using System.Security.Cryptography;
using Klassd.Auth.Abstractions;
using Fido2NetLib;
using Fido2NetLib.Objects;

namespace Klassd.Auth.Passkeys;

/// <summary>
/// Orchestrates the WebAuthn registration and authentication ceremonies on top of Fido2NetLib and
/// the credential store. HTTP concerns (the ceremony cookie, and issuing a session/cookie on
/// success) live in the endpoints — this service only produces ceremony options and verifies the
/// browser's responses against stored credentials.
/// </summary>
public sealed class PasskeyService(IFido2 fido2, IPasskeyCredentialStore credentials, IUserStore users)
{
    /// <summary>Builds registration options for an authenticated user, excluding their existing passkeys.</summary>
    public async Task<CredentialCreateOptions> CreateRegistrationOptionsAsync(
        string userId, string userName, string displayName, CancellationToken ct = default)
    {
        var existing = await credentials.GetByUserIdAsync(userId, ct);

        // A WebAuthn user handle is opaque and per-user; mint one on first registration and reuse it.
        var userHandle = existing.Count > 0 ? existing[0].UserHandle : RandomNumberGenerator.GetBytes(32);

        return fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User { Id = userHandle, Name = userName, DisplayName = displayName },
            ExcludeCredentials = existing.Select(c => new PublicKeyCredentialDescriptor(c.CredentialId)).ToList(),
            AuthenticatorSelection = AuthenticatorSelection.Default,
            AttestationPreference = AttestationConveyancePreference.None,
        });
    }

    /// <summary>Verifies an attestation, persists the new credential, and returns it.</summary>
    public async Task<PasskeyCredential> VerifyRegistrationAsync(
        string userId, AuthenticatorAttestationRawResponse response, CredentialCreateOptions originalOptions,
        string? nickname = null, CancellationToken ct = default)
    {
        var result = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = originalOptions,
            IsCredentialIdUniqueToUserCallback = async (args, _) =>
                await credentials.FindByCredentialIdAsync(args.CredentialId, ct) is null,
        });

        var credential = new PasskeyCredential
        {
            Id = Guid.NewGuid().ToString("N"),
            UserId = userId,
            CredentialId = result.Id,
            PublicKey = result.PublicKey,
            UserHandle = originalOptions.User.Id,
            SignCount = result.SignCount,
            AaGuid = result.AaGuid,
            CredType = result.Type.ToString(),
            Nickname = nickname,
            CreatedAt = DateTimeOffset.UtcNow,
        };
        await credentials.AddAsync(credential, ct);
        return credential;
    }

    /// <summary>
    /// Builds assertion options. Pass <paramref name="userId"/> to restrict to that user's credentials,
    /// or null for a usernameless/discoverable-credential login.
    /// </summary>
    public async Task<AssertionOptions> CreateAssertionOptionsAsync(string? userId, CancellationToken ct = default)
    {
        var allowed = userId is null
            ? []
            : (await credentials.GetByUserIdAsync(userId, ct))
                .Select(c => new PublicKeyCredentialDescriptor(c.CredentialId)).ToList();

        return fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowed,
            UserVerification = UserVerificationRequirement.Preferred,
        });
    }

    /// <summary>
    /// Verifies an assertion against the stored credential, advances the signature counter, and
    /// returns the owning user. Returns null if the credential is unknown or the user is disabled.
    /// </summary>
    public async Task<User?> VerifyAssertionAsync(
        AuthenticatorAssertionRawResponse response, AssertionOptions originalOptions, CancellationToken ct = default)
    {
        var stored = await credentials.FindByCredentialIdAsync(response.RawId, ct);
        if (stored is null) return null;

        var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = originalOptions,
            StoredPublicKey = stored.PublicKey,
            StoredSignatureCounter = (uint)stored.SignCount,
            IsUserHandleOwnerOfCredentialIdCallback = async (args, _) =>
            {
                var byHandle = await credentials.GetByUserHandleAsync(args.UserHandle, ct);
                return byHandle.Any(c => c.CredentialId.AsSpan().SequenceEqual(args.CredentialId));
            },
        });

        await credentials.UpdateSignCountAsync(stored.CredentialId, result.SignCount, DateTimeOffset.UtcNow, ct);

        var user = await users.FindByIdAsync(stored.UserId, ct);
        return user is { Disabled: false } ? user : null;
    }
}

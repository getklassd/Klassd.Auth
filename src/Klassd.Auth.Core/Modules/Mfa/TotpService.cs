using System.Web;
using OtpNet;

namespace Klassd.Auth.Core.Modules.Mfa;

public sealed record TotpEnrollment(string Secret, string OtpAuthUri);

/// <summary>TOTP second factor. Override via <c>auth.Override&lt;ITotpService&gt;(…)</c>.</summary>
public interface ITotpService
{
    TotpEnrollment GenerateSecret(string accountLabel, string issuer = "Klassd.Auth");
    bool VerifyCode(string base32Secret, string code);
}

/// <summary>
/// TOTP second factor (RFC 6238) via Otp.NET. Enrollment returns a base32 secret + an otpauth://
/// URI for QR rendering; persist the secret (encrypted) against the user and verify on step-up.
/// </summary>
public sealed class TotpService : ITotpService
{
    public TotpEnrollment GenerateSecret(string accountLabel, string issuer = "Klassd.Auth")
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        var base32 = Base32Encoding.ToString(key);
        var uri = $"otpauth://totp/{HttpUtility.UrlEncode(issuer)}:{HttpUtility.UrlEncode(accountLabel)}"
                + $"?secret={base32}&issuer={HttpUtility.UrlEncode(issuer)}&algorithm=SHA1&digits=6&period=30";
        return new TotpEnrollment(base32, uri);
    }

    public bool VerifyCode(string base32Secret, string code)
    {
        var totp = new Totp(Base32Encoding.ToBytes(base32Secret));
        return totp.VerifyTotp(code, out _, new VerificationWindow(previous: 1, future: 1)); // ±1 step drift
    }
}

/// <summary>Forwarding base for overriding <see cref="ITotpService"/>; override selectively, call <c>base</c> for the original.</summary>
public abstract class TotpServiceDecorator(ITotpService inner) : ITotpService
{
    public virtual TotpEnrollment GenerateSecret(string accountLabel, string issuer = "Klassd.Auth") =>
        inner.GenerateSecret(accountLabel, issuer);

    public virtual bool VerifyCode(string base32Secret, string code) => inner.VerifyCode(base32Secret, code);
}

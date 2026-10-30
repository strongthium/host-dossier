using System.Security.Cryptography;
using System.Text;

namespace Strongthium.HostDossier.App;

/// <summary>Cloudflare tokens are kept encrypted by Windows for this user (DPAPI), and decrypted only in memory: the
/// settings file on its own, copied elsewhere, gives nothing away.</summary>
internal static class Secrets
{
    public static string Protect(string token) =>
        Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(token), null, DataProtectionScope.CurrentUser));

    public static string? Unprotect(string protectedToken)
    {
        try
        {
            return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(protectedToken), null, DataProtectionScope.CurrentUser));
        }
        catch (Exception exception) when (exception is CryptographicException or FormatException)
        {
            // Encrypted by another user or on another PC: it has to be entered again.
            return null;
        }
    }

    public static Settings LoadSettings(string file)
    {
        var settings = Settings.Load(file);
        foreach (var account in settings.CloudflareAccounts) account.Token = Unprotect(account.Protected);
        return settings;
    }
}

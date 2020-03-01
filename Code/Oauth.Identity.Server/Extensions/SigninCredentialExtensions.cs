using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Oauth.Identity.Server.Extensions
{
    /// <summary>
    /// Implementación para añadir certificado desde configuración en appsettings.json
    /// "SigninKeyCredentials": {
    ///     "KeyType": "KeyFile",
    ///     "KeyFilePath": "C:\\certificates\\idsv4.pfx",
    ///     "KeyStorePath": ""
    ///     ...
    ///     ...
    ///     ...
    ///     ...
    /// }
    /// </summary>
    public static class SigninCredentialExtensions
    {
        private const string KeyType = "KeyType";
        private const string KeyTypeKeyFile = "KeyFile";
        private const string KeyTypeKeyStore = "KeyStore";
        private const string KeyTypeDeveloper = "Developer";
        private const string KeyFilePath = "KeyFilePath";
        private const string KeyFilePassword = "KeyFilePassword";
        private const string KeyStoreIssuer = "KeyStoreIssuer";

        public static IIdentityServerBuilder AddSigninCredentialFromConfig(
            this IIdentityServerBuilder builder, IConfigurationSection options)
        {
            var keyType = options.GetValue<string>(KeyType);
            Log.Debug($"SigninCredentialExtension keyType is {keyType}");

            switch (keyType)
            {
                case KeyTypeDeveloper:
                    Log.Debug($"SigninCredentialExtension adding Developer Signing Credential");
                    builder.AddDeveloperSigningCredential();
                    break;

                case KeyTypeKeyFile:
                    AddCertificateFromFile(builder, options);
                    break;

                case KeyTypeKeyStore:
                    AddCertificateFromStore(builder, options);
                    break;
            }

            return builder;
        }

        private static void AddCertificateFromStore(IIdentityServerBuilder builder, IConfigurationSection options)
        {
            var keyIssuer = options.GetValue<string>(KeyStoreIssuer);
            Log.Debug($"SigninCredentialExtension adding key from store by {keyIssuer}");

            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            var certificates = store.Certificates.Find(X509FindType.FindByIssuerName, keyIssuer, true);

            if (certificates.Count > 0)
                builder.AddSigningCredential(certificates[0]);
            else
                Log.Error("A matching key couldn't be found in the store");
        }

        private static void AddCertificateFromFile(IIdentityServerBuilder builder, IConfigurationSection options)
        {
            var keyFilePath = options.GetValue<string>(KeyFilePath);
            var keyFilePassword = options.GetValue<string>(KeyFilePassword);

            if (File.Exists(keyFilePath))
            {
                Log.Debug($"SigninCredentialExtension adding key from file {keyFilePath}");
                builder.AddSigningCredential(new X509Certificate2(keyFilePath, keyFilePassword, X509KeyStorageFlags.EphemeralKeySet));
            }
            else
            {
                Log.Error($"SigninCredentialExtension cannot find key file {keyFilePath}");
            }
        }
    }
}
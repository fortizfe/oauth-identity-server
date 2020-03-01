using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using Oauth.Identity.Models.Models;
using System.Collections.Generic;

namespace Oauth.Identity.Server.AppConfig
{
    public static class IdentityResourcesConfig
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Phone(),
                new IdentityResources.Email(),
                new IdentityResource
                {
                    Name = "roles",
                    UserClaims = new List<string> { JwtClaimTypes.Role }
                }
            };
        }

        public static IEnumerable<ApiResource> GetApis()
        {
            return new ApiResource[]
            {
                new ApiResource("ApiTemplateApi", "Api template", new List<string>() { JwtClaimTypes.Subject, JwtClaimTypes.Name, JwtClaimTypes.Email, JwtClaimTypes.Role })
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new[]
            {
                // Sample client using client credentials flow
                new Client
                {
                    ClientId = "ClientCredentials",
                    ClientName = "Cliente para flow client credentials",

                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = { new Secret("538D080E-BDF6-4178-8F07-29AFBCFD755F".Sha256()) },

                    AllowedScopes = { "ApiTemplateApi" }
                },

                // Sample of MVC client using hybrid flow
                new Client
                {
                    ClientId = "mvc",
                    ClientName = "MVC Client",

                    AllowedGrantTypes = GrantTypes.HybridAndClientCredentials,
                    ClientSecrets = { new Secret("49C1A7E1-0C79-4A89-A3D6-A37998FB86B0".Sha256()) },

                    RedirectUris = { "http://localhost:5001/signin-oidc" },
                    //FrontChannelLogoutUri = "http://localhost:5001/signout-oidc",
                    PostLogoutRedirectUris = { "http://localhost:5001/signout-callback-oidc" },

                    AllowOfflineAccess = true,
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.OfflineAccess,
                        IdentityServerConstants.StandardScopes.Email,
                        IdentityServerConstants.StandardScopes.Phone,
                        "roles",
                        "ApiTemplateApi"
                    }
                },

                // Sample of SPA client using code flow + pkce
                new Client
                {
                    ClientId = "spa",
                    ClientName = "SPA Client",
                    ClientUri = "http://identityserver.io",

                    AllowedGrantTypes = GrantTypes.Code,
                    RequirePkce = true,
                    RequireClientSecret = false,

                    RedirectUris =
                    {
                        "http://localhost:5002/index.html",
                        "http://localhost:5002/callback.html",
                        "http://localhost:5002/silent.html",
                        "http://localhost:5002/popup.html",
                    },

                    PostLogoutRedirectUris = { "http://localhost:5002/index.html" },
                    AllowedCorsOrigins = { "http://localhost:5002" },

                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.OfflineAccess,
                        IdentityServerConstants.StandardScopes.Email,
                        IdentityServerConstants.StandardScopes.Phone,
                        "roles",
                        "ApiTemplateApi"
                    }
                }
            };
        }
    }

    public static class UserResourcesConfig
    {
        public static IEnumerable<(User user, string pass)> GetUsers()
        {
            return new[]
            {
                (
                    new User
                    {
                        UserName = "Admin",
                        Email = "email@email.com",
                        PhoneNumber = "612345678"
                    },
                    "Admin_1234"
                )
            };
        }

        public static IEnumerable<Role> GetRoles()
        {
            return new[]
            {
                new Role
                {
                    Name = "USER_MANAGER"
                }
            };
        }

        public static IEnumerable<(string userName, string roleName)> GetUserRoles()
        {
            return new[]
            {
                (
                    "Admin",
                    "USER_MANAGER"
                )
            };
        }
    }
}
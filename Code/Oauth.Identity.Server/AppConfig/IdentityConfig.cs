using Oauth.Identity.Server.Context;
using Oauth.Identity.Server.Extensions;
using Oauth.Identity.Models.Models;
using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Reflection;

namespace Oauth.Identity.Server.AppConfig
{
    public static class IdentityConfig
    {
        public static void ConfigureIdentity(this IServiceCollection services, IConfiguration Configuration)
        {
            var connectionString = Configuration.GetConnectionString("IS4Connection");
            var execAssemblyName = Assembly.GetExecutingAssembly().FullName;

            // Config the windows authentication
            // Note Windows Authentication must also be enabled in IIS for this to work.
            services.Configure<IISOptions>(options =>
            {
                options.AutomaticAuthentication = false;
                options.AuthenticationDisplayName = "Windows";
            });

            services.AddIdentity<User, Role>(options =>
            {
                // Config identity here (required email, password characters, etc)
            })
            .AddEntityFrameworkStores<CoreIdentityDbContext>()
            .AddDefaultTokenProviders();

            var identityServerConfig = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;
            }).AddAspNetIdentity<User>();

            // Configuración de persistencia en sql server. Configuración recomendada
            identityServerConfig
                .AddSigninCredentialFromConfig(Configuration.GetSection("SigninKeyCredentials"))
                // this adds the config data from DB (clients, resources, CORS)
                .AddConfigurationStore(options =>
                {
                    options.ConfigureDbContext = builder => builder.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(execAssemblyName));
                })
                // this adds the operational data from DB (codes, tokens, consents)
                .AddOperationalStore(options =>
                {
                    options.ConfigureDbContext = builder => builder.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(execAssemblyName));

                    // this enables automatic token cleanup. this is optional.
                    options.EnableTokenCleanup = true;
                });

            // Usar la configuración en memoria únicamente con fines de desarrollo
            //identityServerConfig
            //    .AddInMemoryApiResources(IdentityResourcesConfig.GetApis())
            //    .AddInMemoryIdentityResources(IdentityResourcesConfig.GetIdentityResources())
            //    .AddInMemoryClients(IdentityResourcesConfig.GetClients())

            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    // register your IdentityServer with Google at https://console.developers.google.com
                    // enable the Google+ API
                    // set the redirect URI to http://localhost:5000/signin-google
                    options.ClientId = "copy client ID from Google here";
                    options.ClientSecret = "copy client secret from Google here";
                })
                .AddOpenIdConnect("aad", "Sign-in with Azure AD", options =>
                {
                    options.Authority = "https://login.microsoftonline.com/common";
                    options.ClientId = "https://leastprivilegelabs.onmicrosoft.com/38196330-e766-4051-ad10-14596c7e97d3";

                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.SignOutScheme = IdentityServerConstants.SignoutScheme;

                    options.ResponseType = "id_token";
                    options.CallbackPath = "/signin-aad";
                    options.SignedOutCallbackPath = "/signout-callback-aad";
                    options.RemoteSignOutPath = "/signout-aad";

                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidAudience = "165b99fd-195f-4d93-a111-3e679246e6a9",

                        NameClaimType = "name",
                        RoleClaimType = "role"
                    };
                })
                .AddFacebook(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                    options.ClientId = "copy client ID from facebook here";
                    options.ClientSecret = "copy client secret from facebook here";
                });
        }
    }
}
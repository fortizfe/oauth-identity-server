using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Oauth.Identity.Models.Models;
using Oauth.Identity.Server.Context;
using System.Linq;
using System.Threading.Tasks;

namespace Oauth.Identity.Server.AppConfig
{
    public static class DatabaseInicializer
    {
        public static void InitializeIdetityContext(IApplicationBuilder app)
        {
            using var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope();
            serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

            var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
            context.Database.Migrate();
            if (!context.Clients.Any())
            {
                foreach (var client in IdentityResourcesConfig.GetClients())
                {
                    context.Clients.Add(client.ToEntity());
                }
                context.SaveChanges();
            }

            if (!context.IdentityResources.Any())
            {
                foreach (var resource in IdentityResourcesConfig.GetIdentityResources())
                {
                    context.IdentityResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }

            if (!context.ApiResources.Any())
            {
                foreach (var resource in IdentityResourcesConfig.GetApis())
                {
                    context.ApiResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }
        }

        public static async Task InitializeCoreContext(IApplicationBuilder app)
        {
            using var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope();
            var context = serviceScope.ServiceProvider.GetRequiredService<CoreIdentityDbContext>();
            var userManager = serviceScope.ServiceProvider.GetRequiredService<UserManager<User>>();
            var roleManager = serviceScope.ServiceProvider.GetRequiredService<RoleManager<Role>>();

            context.Database.Migrate();
            if (!context.Users.Any())
            {
                foreach (var (user, pass) in UserResourcesConfig.GetUsers())
                {
                    await userManager.CreateAsync(user, pass).ConfigureAwait(false);
                }
                context.SaveChanges();
            }

            if (!context.Roles.Any())
            {
                foreach (var role in UserResourcesConfig.GetRoles())
                {
                    await roleManager.CreateAsync(role).ConfigureAwait(false);
                }
                context.SaveChanges();
            }

            if (!context.UserRoles.Any())
            {
                foreach (var (userName, roleName) in UserResourcesConfig.GetUserRoles())
                {
                    var role = roleManager.Roles.FirstOrDefault(r => r.Name == roleName);
                    var user = userManager.Users.FirstOrDefault(u => u.UserName == userName);

                    await userManager.AddToRoleAsync(user, role.Name).ConfigureAwait(false);
                }
                context.SaveChanges();
            }
        }
    }
}
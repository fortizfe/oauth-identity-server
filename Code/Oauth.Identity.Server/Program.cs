using Microsoft.AspNetCore.Hosting;
using System;
using Serilog;
using Microsoft.Extensions.Hosting;

namespace Oauth.Identity.Server
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.Title = "Oauth.Identity";

            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder
                    .UseStartup<Startup>()
                    .UseSerilog((hostingContext, loggerConfiguration) => loggerConfiguration.ReadFrom.Configuration(hostingContext.Configuration));
                });
    }
}
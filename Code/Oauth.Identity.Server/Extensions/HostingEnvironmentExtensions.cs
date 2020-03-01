using Microsoft.Extensions.Hosting;

namespace Microsoft.AspNetCore.Hosting
{
    public static class HostingEnvironmentExtensions
    {
        private const string debug = "debug";
        private const string release = "release";

        public static bool IsDebug(this IWebHostEnvironment hostingEnvironment)
        {
            return hostingEnvironment.IsEnvironment(debug);
        }

        public static bool IsRelease(this IWebHostEnvironment hostingEnvironment)
        {
            return hostingEnvironment.IsEnvironment(release);
        }
    }
}
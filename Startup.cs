using System.Web.Http;
using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin;
using Owin;
using TestWebApiSample;

[assembly: OwinStartup(typeof(Startup))]

namespace TestWebApiSample
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.Map("/web-api", webApiAppBuilder =>
            {
                var _webApiConfig = new HttpConfiguration();
                var _serviceUri = "https://192.168.103.66/identity";

                webApiAppBuilder.UseIdentityServerBearerTokenAuthentication(
                    new IdentityServerBearerTokenAuthenticationOptions
                    {
                        Authority = _serviceUri,
                        RequiredScopes = new[] {"api1"},
                        DelayLoadMetadata = true
                    });

                webApiAppBuilder.UseWebApi(_webApiConfig);
            });
        }
    }
}
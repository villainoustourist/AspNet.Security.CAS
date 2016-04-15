using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Http.Features.Authentication;
using Microsoft.Extensions.Logging;

namespace AspNet.Security.CAS
{
    internal class CasHandler : RemoteAuthenticationHandler<CasOptions>
    {
        private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();
        private const string StateCookie = "__CasState";
        private readonly HttpClient _httpClient;

        private const string CorrelationPrefix = ".AspNetCore.Correlation.";
        private const string CorrelationProperty = ".xsrf";
        private const string CorrelationMarker = "N";

        public CasHandler(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }
        
        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = new AuthenticationProperties(context.Properties);
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            var returnTo = BuildReturnTo(Options.StateDataFormat.Protect(properties));

            var authorizationEndpoint = $"{Options.CasServerUrlBase}/login?service={Uri.EscapeDataString(returnTo)}";
            
            var redirectContext = new CasRedirectToAuthorizationEndpointContext(
                Context, Options,
                properties, authorizationEndpoint);
            await Options.Events.RedirectToAuthorizationEndpoint(redirectContext);
            return true;
        }

        protected override async Task<AuthenticateResult> HandleRemoteAuthenticateAsync()
        {
            var query = Request.Query;
            var state = query["state"];

            var properties = Options.StateDataFormat.Unprotect(state);
            if (properties == null)
            {
                return AuthenticateResult.Failed("The state was missing or invalid.");
            }

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps
            };
            Response.Cookies.Delete(StateCookie, cookieOptions);

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return AuthenticateResult.Failed("Correlation failed.");
            }

            var ticket = query["ticket"];
            if (string.IsNullOrEmpty(ticket))
            {
                return AuthenticateResult.Failed("Missing CAS ticket.");
            }
            
            var service = Uri.EscapeDataString(BuildReturnTo(state));

            return await Options.TicketValidator.ValidateTicket(Context, _httpClient, properties, ticket, service);
        }
        
        private string BuildReturnTo(string state)
        {
            return Request.Scheme + "://" + Request.Host +
               Request.PathBase + Options.CallbackPath +
                "?state=" + Uri.EscapeDataString(state);
        }
     
        protected void GenerateCorrelationId(AuthenticationProperties properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            var bytes = new byte[32];
            CryptoRandom.GetBytes(bytes);
            var correlationId = Base64UrlTextEncoder.Encode(bytes);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps,
                Expires = DateTime.UtcNow.Add(TimeSpan.FromMinutes(5))
            };

            properties.Items[CorrelationProperty] = correlationId;

            var cookieName = CorrelationPrefix + Options.AuthenticationScheme + "." + correlationId;

            Response.Cookies.Append(cookieName, CorrelationMarker, cookieOptions);
        }

        protected bool ValidateCorrelationId(AuthenticationProperties properties)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            string correlationId;
            if (!properties.Items.TryGetValue(CorrelationProperty, out correlationId))
            {
                Logger.LogCritical($"Correlation Property Not Found.  Name: {CorrelationPrefix}");
                return false;
            }

            properties.Items.Remove(CorrelationProperty);

            var cookieName = CorrelationPrefix + Options.AuthenticationScheme + "." + correlationId;

            var correlationCookie = Request.Cookies[cookieName];
            if (string.IsNullOrEmpty(correlationCookie))
            {
                Logger.LogCritical($"Correlation Cookie Not Found.  Name: {cookieName}");
                return false;
            }

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsHttps
            };
            Response.Cookies.Delete(cookieName, cookieOptions);

            if (!string.Equals(correlationCookie, CorrelationMarker, StringComparison.Ordinal))
            {
                Logger.LogCritical($"Unexpected Correlation Cookie Value.  Name: {cookieName} Value: {correlationCookie}");
                return false;
            }

            return true;
        }
    }
}

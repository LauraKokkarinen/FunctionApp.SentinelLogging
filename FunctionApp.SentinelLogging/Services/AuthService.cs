using Azure.Core;
using Azure.Identity;
using FunctionApp.SentinelLogging.Interfaces;
using Microsoft.Extensions.Configuration;
using System.Diagnostics;

namespace FunctionApp.SentinelLogging.Services
{
    public class AuthService(IConfiguration configuration) : IAuthService
    {
        private readonly string? _tenantId = configuration["TenantId"];
        private readonly string? _clientId = configuration["ClientId"];
        private readonly string? _clientSecret = configuration["ClientSecret"];

        public async Task<string> GetAccessTokenAsync(string resourceUrl)
        {
            string token;

            if (Debugger.IsAttached)
            {
                if (_tenantId == null || _clientId == null || _clientSecret == null)
                    throw new Exception($"TenantId, ClientId or ClientSecret is null.");
                token = await GetAccessTokenWithClientSecretAsync(resourceUrl, _tenantId, _clientId, _clientSecret);
            }
            else
                token = await GetAccessTokenWithManagedIdentityAsync(resourceUrl);

            return token;
        }

        private static async Task<string> GetAccessTokenWithClientSecretAsync(string resourceUrl, string tenantId, string clientId, string clientSecret)
        {
            return await GetToken(new ClientSecretCredential(tenantId, clientId, clientSecret), resourceUrl);
        }

        private static async Task<string> GetAccessTokenWithManagedIdentityAsync(string resourceUrl)
        {
            return await GetToken(new ManagedIdentityCredential(), resourceUrl);
        }

        private static async Task<string> GetToken(TokenCredential credential, string resourceUrl)
        {
            return (await credential.GetTokenAsync(new TokenRequestContext(scopes: [resourceUrl + "/.default"]) { }, new CancellationToken())).Token;
        }
    }
}
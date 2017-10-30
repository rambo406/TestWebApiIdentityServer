using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web.Mvc;
using IdentityModel;
using IdentityModel.Client;

namespace TestWebApiSample.Controllers
{
    [AllowAnonymous]
    public class IdentityController : Controller
    {
        private class Nonce
        {
            public Nonce(int expiredSeconds)
            {
                CreateDateTime = DateTime.Now.AddSeconds(expiredSeconds);
                Key = CryptoRandom.CreateUniqueId();
            }

            public DateTime CreateDateTime { get; }

            public string Key { get; }
        }

        private const string ClientID = "tlp";
        private const string ClientSecret = "secret";
        private const string IdentityServerHostName = "http://localhost:5000";
        private const int NonceExpireSeconds = 30;

        private static readonly ConcurrentDictionary<string, Nonce> NonceStore = new ConcurrentDictionary<string, Nonce>();

        private void AddNonce(Nonce nonce)
        {
            NonceStore.AddOrUpdate(nonce.Key, nonce, (guid, localNonce) => localNonce);

            var _expiredNonce = NonceStore.Where(x => x.Value.CreateDateTime < DateTime.Now).ToList();

            foreach (var expiredNonce in _expiredNonce)
            {
                NonceStore.TryRemove(expiredNonce.Key, out _);
            }
        }

        public async Task<ActionResult> Callback(string id_token, string code, string nonce)
        {
            var _discovery = await GetDiscovery();
            var _securityKeys = new List<SecurityKey>();

            foreach (var webKey in _discovery.KeySet.Keys)
            {
                var rsa = new RsaSecurityKey(new RSAParameters
                {
                    Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                    Exponent = Base64UrlEncoder.DecodeBytes(webKey.E)
                });
                rsa.KeyId = webKey.Kid;

                _securityKeys.Add(rsa);
            }

            // validate id_token
            var _parameters = new TokenValidationParameters
            {
                ValidIssuer = IdentityServerHostName,
                ValidAudience = "tlp",
                IssuerSigningKeys = _securityKeys
            };

            var _handler = new JwtSecurityTokenHandler();
            _handler.InboundClaimTypeMap.Clear();

            var _validateToken = _handler.ValidateToken(id_token, _parameters, out _);
            var _nonce = _validateToken.Claims.First(x => x.Type == "nonce").Value;

            if (!NonceStore.ContainsKey(_nonce))
            {
                throw new InvalidOperationException("invalid nonce key");
            }

            NonceStore.TryRemove(_nonce, out _);

            // open back channel to get access/refresh tokens
            var _tokenClient = new TokenClient(_discovery.TokenEndpoint, ClientID, ClientSecret);
            var _tokenResponse = await _tokenClient.RequestAuthorizationCodeAsync(code, GetCallbackUrl());

            return null;
        }

        private string GetCallbackUrl()
        {
            return Url.Action("Callback", "Identity", null, Url.RequestContext.HttpContext.Request.Url.Scheme);
        }

        private async Task<DiscoveryResponse> GetDiscovery()
        {
            return await DiscoveryClient.GetAsync(IdentityServerHostName);
        }

        public async Task<ActionResult> StartAuthentication()
        {
            if (!User.Identity.IsAuthenticated)
            {
                var _nonce = new Nonce(NonceExpireSeconds);
                var _callbackUrl = GetCallbackUrl();
                var _discovery = await GetDiscovery();
                var _url = _discovery.AuthorizeEndpoint +
                           $"?client_id={ClientID}" +
                           $"&redirect_uri={_callbackUrl}" +
                           "&response_type=code id_token" +
                           "&response_mode=form_post" +
                           $"&nonce={_nonce.Key}" +
                           "&scope=openid api1";

                AddNonce(_nonce);

                return Redirect(_url);
            }

            return RedirectToAction("Index", "Home");
        }
    }
}
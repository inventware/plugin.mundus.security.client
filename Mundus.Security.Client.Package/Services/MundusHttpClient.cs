using Microsoft.AspNetCore.Http;
using Mundus.Security.Client.Configuration;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;


namespace Mundus.Security.Client.Services
{
    public class MundusHttpClient
    {
        private readonly HttpClient _httpClient;
        private readonly MundusConfigurationOptions _options;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public MundusHttpClient(HttpClient httpClient, MundusConfigurationOptions options, 
            IHttpContextAccessor httpContextAccessor)
        {
            _httpClient = httpClient 
                ?? throw new ArgumentNullException(nameof(httpClient));

            _options = options 
                ?? throw new ArgumentNullException(nameof(options));

            _httpContextAccessor = httpContextAccessor 
                ?? throw new ArgumentNullException(nameof(httpContextAccessor));

            if (_httpClient.BaseAddress == null && !string.IsNullOrWhiteSpace(_options.SecurityUrl)){
                _httpClient.BaseAddress = new Uri(_options.SecurityUrl);
            }
        }

        public string ApplicationCode => _options.ApplicationCode;

        public string CompanyCode => _options.CompanyCode;


        public async Task<HttpResponseMessage> PostToMundusSecurityAsync<T>(string relativePath, T payload)
        {
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Post, requestUri);

            PrepareRequestHeaders(request);
            request.Content = JsonContent.Create(payload);

            try
            {
                return await _httpClient.SendAsync(request).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Mundus Security platform is " +
                    "inaccessible.", ex);
            }
        }


        public async Task<HttpResponseMessage> PutToMundusSecurityAsync<T>(string relativePath, T payload)
        {
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Put, requestUri);

            PrepareRequestHeaders(request);
            request.Content = JsonContent.Create(payload);

            try
            {
                return await _httpClient.SendAsync(request).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Mundus Security platform is " +
                    "inaccessible.", ex);
            }
        }


        public async Task<HttpResponseMessage> DeleteFromMundusSecurityAsync(string relativePath)
        {
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Delete, requestUri);

            PrepareRequestHeaders(request);

            try
            {
                return await _httpClient.SendAsync(request).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Mundus Security platform is " +
                    "inaccessible.", ex);
            }
        }


        public async Task<HttpResponseMessage> GetFromMundusSecurityAsync(string relativePath)
        {
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);

            PrepareRequestHeaders(request);

            try
            {
                return await _httpClient.SendAsync(request).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Mundus Security platform is " +
                    "inaccessible.", ex);
            }
        }


        public async Task<HttpResponseMessage> PostToMundusSecurityAsMachineAsync<T>(string relativePath, T payload)
        {
            try
            {
                var machineToken = await GetMachineTokenAsync().ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(machineToken)){
                    throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Failed to obtain machine token from " +
                        "Mundus Security.");
                }

                var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityUrl), relativePath);
                using var request = new HttpRequestMessage(HttpMethod.Post, requestUri);

                // Adds headers strictly isolated to this request.
                request.Headers.Add("X-Application-Code", _options.ApplicationCode);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", machineToken);
                request.Content = JsonContent.Create(payload);

                return await _httpClient.SendAsync(request).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Mundus Security platform is " +
                    "inaccessible.", ex);
            }
        }


        private async Task<string?> GetMachineTokenAsync()
        {
            var tokenRequestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityUrl), 
                "administration/m2m/connect/token");

            var credentialsPayload = new
            {
                applicationCode = _options.ApplicationCode,
                companyCode = _options.CompanyCode,
                grantType = "client_credentials",
                clientId = _options.ClientId,
                clientSecret = _options.ClientSecret
            };

            using var request = new HttpRequestMessage(HttpMethod.Post, tokenRequestUri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Content = JsonContent.Create(credentialsPayload);

            HttpResponseMessage tokenResponse;
            try
            {
                tokenResponse = await _httpClient.SendAsync(request).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Mundus Security platform is inaccessible.", ex);
            }

            using (tokenResponse)
            {
                var tokenJson = await tokenResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
                if (!tokenResponse.IsSuccessStatusCode)
                {
                    throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Token endpoint request failed. " +
                        $"URI: '{tokenRequestUri}'. " +
                        $"Status: {(int)tokenResponse.StatusCode} {tokenResponse.ReasonPhrase}. " +
                        $"Response: {tokenJson}");
                }

                using var doc = JsonDocument.Parse(tokenJson);
                if (doc.RootElement.TryGetProperty("token", out var t) ||
                    doc.RootElement.TryGetProperty("access_token", out t))
                {
                    return t.GetString();
                }
            }

            throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Invalid token response: 'token' or " +
                "'access_token' field missing.");
        }


        private void PrepareRequestHeaders(HttpRequestMessage request)
        {
            // Adds X-Application-Code isolated to this request message.
            if (!string.IsNullOrWhiteSpace(_options.ApplicationCode)){
                request.Headers.Add("X-Application-Code", _options.ApplicationCode);
            }

            // Copies the logged-in user token, if present, isolated to this request message.
            try
            {
                var headers = _httpContextAccessor?.HttpContext?.Request?.Headers;
                if (headers != null && headers.TryGetValue("Authorization", out var authValues))
                {
                    var headerValue = authValues.FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(headerValue)){
                        request.Headers.Authorization = AuthenticationHeaderValue.Parse(headerValue);
                    }
                }
            }
            catch
            {
                // Swallow: keeps resilience if parsing fails.
            }
        }
    }
}
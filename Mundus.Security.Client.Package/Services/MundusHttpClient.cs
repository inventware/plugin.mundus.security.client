using Microsoft.AspNetCore.Http;
using Mundus.Security.Client.Configuration;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
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

            if (_httpClient.BaseAddress == null && !string.IsNullOrWhiteSpace(_options.SecurityDestinationUrl)){
                _httpClient.BaseAddress = new Uri(_options.SecurityDestinationUrl);
            }
        }


        public string ApplicationCode => _options.ApplicationCode;

        public string CompanyCode => _options.CompanyCode;

        public string ClientId => _options.ClientId;

        public string ClientSecret => _options.ClientSecret;


        #region HttpClient Methods for User Requests

        public async Task<HttpResponseMessage> GetFromMundusSecurityAsync(string relativePath)
        {
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityDestinationUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);

            PrepareRequestHeaders(request, attachUserToken: true);

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


        /// <summary>
        /// This method can receive any DTO object in a GET method and automatically transform it into a Query String
        /// [FromQuery]. 
        /// </summary>
        public async Task<HttpResponseMessage> GetFromMundusSecurityAsync<T>(string relativePath, T queryParameters) 
            where T : class
        {
            if (queryParameters == null){
                return await GetFromMundusSecurityAsync(relativePath).ConfigureAwait(false);
            }

            // Automatically converts DTO properties into a query string.
            var properties = from p in queryParameters.GetType().GetProperties()
                             let value = p.GetValue(queryParameters, null)
                             where value != null
                             select $"{p.Name}={Uri.EscapeDataString(value.ToString()!)}";

            var queryString = string.Join("&", properties);

            // Combines the path with the query string and the generated parameters.
            var cleanPath = relativePath;
            if (!string.IsNullOrWhiteSpace(queryString))
            {
                cleanPath = relativePath.Contains("?")
                ? $"{relativePath}&{queryString}"
                : $"{relativePath}?{queryString}";
            }

            var requestUri = new Uri(_httpClient.BaseAddress 
                ?? new Uri(_options.SecurityDestinationUrl), cleanPath);

            using var request =
                new HttpRequestMessage(HttpMethod.Get, requestUri);

            PrepareRequestHeaders(request);

            return await _httpClient.SendAsync(request);

            // Dispatches to the agnostic GET method that is already protected and resilient.
            //return await GetFromMundusSecurityAsync(cleanPath).ConfigureAwait(false);
        }


        public async Task<HttpResponseMessage> PostToMundusSecurityAsync<T>(string relativePath, T payload)
        {
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityDestinationUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Post, requestUri);

            PrepareRequestHeaders(request, attachUserToken: true);

            // Explicitly serializing the JSON to a string in RAM before sending. This forces .NET to populate the
            // exact 'Content-Length' header (in bytes) and disables 'Transfer-Encoding: chunked', thereby avoiding
            // issues with stream parsing on the Mundus Security server.
            string jsonString = JsonSerializer.Serialize(payload);
            request.Content = new StringContent(jsonString, Encoding.UTF8, "application/json");

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
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityDestinationUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Put, requestUri);

            PrepareRequestHeaders(request, attachUserToken: true);

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
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityDestinationUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Delete, requestUri);

            PrepareRequestHeaders(request, attachUserToken: true);

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


        public async Task<HttpResponseMessage> DeleteFromMundusSecurityAsync<T>(string relativePath, T payload)
        {
            var requestUri = new Uri(_httpClient.BaseAddress ?? new Uri(_options.SecurityDestinationUrl), relativePath);
            using var request = new HttpRequestMessage(HttpMethod.Delete, requestUri);

            PrepareRequestHeaders(request, attachUserToken: true);

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


        private void PrepareRequestHeaders(HttpRequestMessage request, bool attachUserToken = true)
        {
            // Adds X-Application-Code isolated to this request message.
            if (!string.IsNullOrWhiteSpace(_options.ApplicationCode))
                request.Headers.Add("X-Application-Code", _options.ApplicationCode);

            if (!string.IsNullOrWhiteSpace(_options.SatelliteOriginUrl))
                request.Headers.Add("X-Origin-Url", _options.SatelliteOriginUrl);

            // 🎯 SAFETY GUARD: Prevents the authentication token from being attached to the outgoing request, avoiding
            // false-positive 400/401 errors at the gateway.
            if (!attachUserToken)
                return;

            // Copies the logged-in user token, if present, isolated to this request message.
            try
            {
                var headers = _httpContextAccessor?.HttpContext?.Request?.Headers;
                if (headers != null && headers.TryGetValue("Authorization", out var authValues))
                {
                    var headerValue = authValues.FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(headerValue))
                        request.Headers.Authorization = AuthenticationHeaderValue.Parse(headerValue);
                }
            }
            catch
            {
                // Swallow: keeps resilience if parsing fails.
            }
        }

        #endregion




        #region HttpClient Methods for Machine-to-Machine (M2M) Requests

        public async Task<HttpResponseMessage> GetFromMundusSecurityAsMachineAsync<T>(string relativePath,
            T queryParameters) where T : class
        {
            try
            {
                var machineToken = await GetMachineTokenAsync().ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(machineToken))
                {
                    throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Failed to obtain machine token from " +
                        "Mundus Security.");
                }

                // Converts DTO properties into a query string (?Param1=Value1&Param2=Value2)
                var cleanPath = relativePath;
                if (queryParameters != null)
                {
                    var properties = from p in typeof(T).GetProperties()
                                     let value = p.GetValue(queryParameters, null)
                                     where value != null
                                     select $"{p.Name}={Uri.EscapeDataString(value.ToString()!)}";

                    var queryString = string.Join("&", properties);

                    if (!string.IsNullOrWhiteSpace(queryString))
                    {
                        cleanPath = relativePath.Contains("?")
                            ? $"{relativePath}&{queryString}"
                            : $"{relativePath}?{queryString}";
                    }
                }

                // Combines final URI with a Query String generated.
                var requestUri = new Uri(_httpClient.BaseAddress 
                    ?? new Uri(_options.SecurityDestinationUrl), cleanPath);

                using var request = LoadRequest(HttpMethod.Get, requestUri, string.Empty);

                // Dispatches the request resiliently via the Polly V8 pool.
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
                if (string.IsNullOrWhiteSpace(machineToken))
                {
                    throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Failed to obtain machine token from " +
                        "Mundus Security.");
                }

                var requestUri = new Uri(_httpClient.BaseAddress
                    ?? new Uri(_options.SecurityDestinationUrl), relativePath);
                
                string jsonString = JsonSerializer.Serialize(payload);
                
                var request = LoadRequest(HttpMethod.Post, requestUri, jsonString);

                var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
                return response;
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Mundus Security platform is " +
                    "inaccessible.", ex);
            }
        }


        public async Task<string?> GetMachineTokenAsync()
        {
            var tokenRequestUri = new Uri(_httpClient.BaseAddress 
                ?? new Uri(_options.SecurityDestinationUrl), "api/v1/administration/m2m/connect/token");

            var requestCredentials = new
            {
                applicationCode = _options.ApplicationCode,
                companyCode = _options.CompanyCode,
                grantType = "client_credentials",
                clientId = _options.ClientId,
                clientSecret = _options.ClientSecret
            };

            // 🎯 Forçando a serialização em bloco sólido na memória RAM (Chunked):
            string jsonSerialized = JsonSerializer.Serialize(requestCredentials);
            using var request = LoadRequest(HttpMethod.Post, tokenRequestUri, jsonSerialized);

            HttpResponseMessage tokenResponse;

            try
            {
                tokenResponse = await _httpClient.SendAsync(request).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Mundus Security platform is inaccessible.",
                    ex);
            }

            return await ParseTokenResponse(tokenResponse, tokenRequestUri);
        }


        private HttpRequestMessage LoadRequest(HttpMethod httpVerb, Uri requestUri, string? jsonSerialized)
        {
            var request = new HttpRequestMessage(httpVerb, requestUri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            if (!string.IsNullOrWhiteSpace(_options.ApplicationCode))
                request.Headers.Add("X-Application-Code", _options.ApplicationCode);
            else
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] A configuração 'ApplicationCode' está " +
                    "ausente.");

            if (!string.IsNullOrWhiteSpace(_options.SatelliteOriginUrl))
                request.Headers.Add("X-Origin-Url", _options.SatelliteOriginUrl);
            else
                throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] A configuração 'SatelliteOriginUrl' está " +
                    "ausente.");

            if (!string.IsNullOrWhiteSpace(jsonSerialized))
            {
                // 🎯 Forçando o CONTENT-TYPE PURO: Removendo o charset do header para não confundir o Gateway do Servidor
                request.Content = new StringContent(jsonSerialized, Encoding.UTF8, "application/json");
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }

            return request;
        }


        private async Task<string?> ParseTokenResponse(HttpResponseMessage tokenResponse, Uri? tokenRequestUri)
        {
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

                using var tokenProperties = JsonDocument.Parse(tokenJson);
                if (tokenProperties.RootElement.TryGetProperty("token", out var accessToken) ||
                    tokenProperties.RootElement.TryGetProperty("access_token", out accessToken))
                {
                    return accessToken.GetString();
                }
            }

            throw new InvalidOperationException("[MUNDUS_SECURITY_ERROR] Invalid token response: 'token' or " +
                "'access_token' field missing.");
        }

        #endregion
    }
}
using FunctionApp.SentinelLogging.Interfaces;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace FunctionApp.SentinelLogging.Services
{
    public class HttpService : IHttpService
    {
        private readonly HttpClient _httpClient;

        public HttpService()
        {
            _httpClient = new HttpClient();
        }

        public async Task<T?> GetResponseAsync<T>(string url, Method method, HttpRequestHeaders? headers = null, string? body = null, string? contentType = null)
        {
            var request = new HttpRequestMessage(new HttpMethod(method.ToString()), url);

            if (headers != null)
            {
                foreach (var header in headers)
                {
                    request.Headers.Add(header.Key, header.Value);
                }
            }

            request.Content = body != null ? new StringContent(body, Encoding.UTF8, contentType ?? "application/json") : null;

            var response = _httpClient.SendAsync(request).Result;

            if (response != null)
            {
                var status = (int)response.StatusCode;
                bool throttled = status == 429;

                if (throttled || status == 502 || status == 504)
                {
                    if (throttled)
                    {
                        var timeSpan = response.Headers.RetryAfter?.Delta?.Seconds;
                        int milliseconds = (timeSpan ?? 5) * 1000;
                        Thread.Sleep(milliseconds);
                    }

                    return await GetResponseAsync<T>(url, method, headers, body, contentType); //retry
                }
            }

            if (request.Headers.FirstOrDefault(header => header.Key == "Accept").Value?.Contains("image/jpg") == true)
            {
                var result = (T?)(object?)response?.Content.ReadAsByteArrayAsync().Result;
                return result;
            }

            var responseBody = await ReadResponseBody<T>(response);

            if (response?.IsSuccessStatusCode == true)
            {
                if (response?.StatusCode == HttpStatusCode.Accepted && response.Headers.Location != null)
                {
                    responseBody = GetResponseHeaders<T>(response);
                }

                return responseBody;
            }
            else
            {
                if (response?.StatusCode == HttpStatusCode.Conflict && response.Headers.Location != null)
                    return GetResponseHeaders<T>(response);

                throw new Exception(responseBody?.ToString() ?? response?.ReasonPhrase);
            }
        }

        private static async Task<T?> ReadResponseBody<T>(HttpResponseMessage? response)
        {
            if (response != null && response?.Content != null)
            {
                try
                {
                    string content = await response.Content.ReadAsStringAsync();
                    return !string.IsNullOrWhiteSpace(content) ? JsonSerializer.Deserialize<T>(content) : default;
                }
                catch (Exception) // Response content is not in JSON format
                {
                    return default;
                }
            }

            return default;
        }

        private static T? GetResponseHeaders<T>(HttpResponseMessage response)
        {
            return JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(response.Headers));
        }
    }

    public enum Method
    {
        Get,
        Post,
        Put,
        Patch,
        Delete
    }
}
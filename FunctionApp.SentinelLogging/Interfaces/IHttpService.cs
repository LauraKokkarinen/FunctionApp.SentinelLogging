using FunctionApp.SentinelLogging.Services;
using System.Net.Http.Headers;

namespace FunctionApp.SentinelLogging.Interfaces
{
    public interface IHttpService
    {
        Task<T?> GetResponseAsync<T>(string url, Method method, HttpRequestHeaders? headers = null, string? body = null, string? contentType = null);
    }
}

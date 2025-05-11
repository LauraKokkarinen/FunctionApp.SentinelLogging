using FunctionApp.SentinelLogging.Interfaces;
using FunctionApp.SentinelLogging.Types;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using System.Text.Json;

namespace FunctionApp.SentinelLogging.Services
{
    public class LogAnalyticsService : ILogAnalyticsService
    {
        public IAuthService _authService;
        public IHttpService _httpService;

        public string _apiUrl;

        // The following properties are used to create the log entry
        public string _appId;
        public string? _hostIp;
        public int _port;
        public string? _requestMethod;
        public string? _protocol;
        public string? _hostName;
        public string? _requestUri;
        public string? _sourceIp;
        public string? _region;
        public string? _geo;
        public string? _userAgent;
        public string? _principalId;

        public LogAnalyticsService(IConfiguration configuration, IAuthService authService, IHttpService httpService)
        {
            _authService = authService;
            _httpService = httpService;

            _appId = configuration["AppId"] ?? throw new Exception("AppId is null");

            var dataSource = configuration["DCR_DataSource"] ?? throw new Exception("DCR_DataSource is null");
            var endpoint = configuration["DCE_LogsIngestionUrl"] ?? throw new Exception("DCE_LogsIngestionUrl is null");
            var immutableId = configuration["DCR_ImmutableId"] ?? throw new Exception("DCR_ImmutableId is null");

            _apiUrl = $"{endpoint}/dataCollectionRules/{immutableId}/streams/{dataSource}?api-version=2023-01-01";
        }

        public async Task Initialize(string hostIp, int port, string requestMethod, string protocol, string hostName, string requestUri, string sourceIp, string userAgent, string? principalId = null)
        {
            _hostIp = hostIp;
            _port = port;
            _requestMethod = requestMethod;
            _protocol = protocol;
            _hostName = hostName;
            _requestUri = requestUri;
            _sourceIp = sourceIp;
            _userAgent = userAgent;

            var geolocation = await GetSourceGeolocation(sourceIp);

            _geo = geolocation?.Country ?? "Unknown";
            _region = geolocation?.RegionName ?? "Unknown";
        }

        private async Task<Geolocation?> GetSourceGeolocation(string sourceIp)
        {
            // The API is free for non-commercial use
            return await _httpService.GetResponseAsync<Geolocation>($"http://ip-api.com/json/{sourceIp}", Method.Get);
        }

        public async Task LogEventAsync(SeverityLevel severityLevel, string eventName, string description)
        {
            var headers = new HttpRequestMessage().Headers;
            headers.TryAddWithoutValidation("Authorization", $"Bearer {await _authService.GetAccessTokenAsync("https://monitor.azure.com")}");

            var body = JsonSerializer.Serialize(new[] { // The API expects an array of log entries
                new LogEntry
                {
                    AppId = _appId,
                    Region = _region,
                    Geo = _geo,
                    Level = severityLevel.ToString(),
                    Event = eventName,
                    Description = description,
                    HostIp = _hostIp,
                    Port = _port,
                    RequestMethod = _requestMethod,
                    Protocol = _protocol,
                    HostName = _hostName,
                    RequestUri = _requestUri,
                    SourceIp = _sourceIp,
                    UserAgent = _userAgent,
                    PrincipalId = _principalId
                }
            });

            await _httpService.GetResponseAsync<object>(_apiUrl, Method.Post, headers, body);
        }
    }
}

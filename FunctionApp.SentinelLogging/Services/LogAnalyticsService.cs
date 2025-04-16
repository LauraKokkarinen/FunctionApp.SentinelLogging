using FunctionApp.SentinelLogging.Interfaces;
using FunctionApp.SentinelLogging.Types;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using System.Diagnostics;
using System.Text.Json;

namespace FunctionApp.SentinelLogging.Services
{
    public class LogAnalyticsService : ILogAnalyticsService
    {
        public IAuthService _authService;
        public IHttpService _httpService;

        public string _uri;
        public string _appId;
        public string _region;
        public string _geo;

        public string? _hostIp;
        public int _port;
        public string? _requestMethod;
        public string? _protocol;
        public string? _hostName;
        public string? _requestUri;
        public string? _sourceIp;
        public string? _userAgent;

        public LogAnalyticsService(IConfiguration configuration, IAuthService authService, IHttpService httpService)
        {
            _authService = authService;
            _httpService = httpService;

            var tableName = configuration["LogAnalyticsTableName"] ?? throw new Exception("LogAnalyticsTableName is null");
            var endpoint = configuration["DataIngestionEndpoint"] ?? throw new Exception("DataIngestionEndpoint is null");
            var immutableId = configuration["DataCollectionRuleId"] ?? throw new Exception("DataCollectionRuleId is null");

            _uri = $"{endpoint}/dataCollectionRules/{immutableId}/streams/{tableName}?api-version=2023-01-01";

            _appId = Debugger.IsAttached ? "00000000-0000-0000-0000-000000000000" : "TODO";
            _region = Debugger.IsAttached ? "West Europe" : "TODO";
            _geo = Debugger.IsAttached ? "Europe" : "TODO";
        }

        public void Initialize(string hostIp, int port, string requestMethod, string protocol, string hostName, string requestUri, string sourceIp, string userAgent)
        {
            _hostIp = hostIp;
            _port = port;
            _requestMethod = requestMethod;
            _protocol = protocol;
            _hostName = hostName;
            _requestUri = requestUri;
            _sourceIp = sourceIp;
            _userAgent = userAgent;
        }

        public async Task LogEventAsync(SeverityLevel severityLevel, string eventName, string description)
        {
            var headers = new HttpRequestMessage().Headers;
            headers.TryAddWithoutValidation("Authorization", $"Bearer {await _authService.GetAccessTokenAsync("https://monitor.azure.com")}");

            var body = JsonSerializer.Serialize(new LogEntry
            {
                Timestamp = DateTime.UtcNow.ToString("o"),
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
                UserAgent = _userAgent
            });

            var response = await _httpService.GetResponseAsync<LogEntry>(_uri, Method.Post, headers, body);
        }
    }
}

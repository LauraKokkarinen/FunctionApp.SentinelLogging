using FunctionApp.SentinelLogging.Interfaces;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace FunctionApp.SentinelLogging.Services
{
    public class LogAnalyticsService(IConfiguration configuration, ILogger<LogAnalyticsService> logger) : ILogAnalyticsService
    {
        public string _endpoint = configuration["LogIngestionEndpoint"] ?? throw new Exception("LogIngestionEndpoint is null");
        public string _tableName = configuration["LogTableName"] ?? throw new Exception("LogTableName is null");

        public string _appId = Debugger.IsAttached ? "00000000-0000-0000-0000-000000000000" : "TODO";
        public string _region = Debugger.IsAttached ? "West Europe" : "TODO";
        public string _geo = Debugger.IsAttached ? "Europe" : "TODO";

        public string? _hostIp;
        public int _port;
        public string? _requestMethod;
        public string? _protocol;
        public string? _hostName;
        public string? _requestUri;
        public string? _sourceIp;
        public string? _userAgent;

        public ILogger<LogAnalyticsService> _logger = logger;

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

        public void LogEvent(SeverityLevel severityLevel, string eventName, string description)
        {
            _logger.LogInformation(
                "{timestamp} {appid} {region} {geo} {level} {event} {description} {host_ip} {port} {request_method} {protocol} {hostname} {request_uri} {source_ip} {useragent} ",
                DateTime.UtcNow.ToString("o"),
                _appId,
                _region,
                _geo,
                severityLevel,
                eventName,
                description,
                _hostIp,
                _port,
                _requestMethod,
                _protocol,
                _hostName,
                _requestUri,
                _sourceIp,
                _userAgent
            );
        }
    }
}

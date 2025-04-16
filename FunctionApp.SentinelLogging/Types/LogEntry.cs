using System.Text.Json.Serialization;

namespace FunctionApp.SentinelLogging.Types
{
    public class LogEntry
    {
        [JsonPropertyName("timestamp")]
        public DateTime? Timestamp { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("appid")]
        public string? AppId { get; set; }

        [JsonPropertyName("region")]
        public string? Region { get; set; }

        [JsonPropertyName("geo")]
        public string? Geo { get; set; }

        [JsonPropertyName("level")]
        public string? Level { get; set; }

        [JsonPropertyName("event")]
        public string? Event { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("host_ip")]
        public string? HostIp { get; set; }

        [JsonPropertyName("port")]
        public int Port { get; set; }

        [JsonPropertyName("request_method")]
        public string? RequestMethod { get; set; }

        [JsonPropertyName("protocol")]
        public string? Protocol { get; set; }

        [JsonPropertyName("hostname")]
        public string? HostName { get; set; }

        [JsonPropertyName("request_uri")]
        public string? RequestUri { get; set; }

        [JsonPropertyName("source_ip")]
        public string? SourceIp { get; set; }

        [JsonPropertyName("useragent")]
        public string? UserAgent { get; set; }

    }
}

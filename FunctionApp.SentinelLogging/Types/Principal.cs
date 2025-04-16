using System.Text.Json.Serialization;

namespace FunctionApp.SentinelLogging.Types
{
    public class Principal
    {
        [JsonPropertyName("auth_typ")]
        public string? AuthType { get; set; }
        [JsonPropertyName("claims")]
        public List<Claim>? Claims { get; set; }
        [JsonPropertyName("name_typ")]
        public string? NameType { get; set; }
        [JsonPropertyName("role_typ")]
        public string? Roletype { get; set; }
    }

    public class Claim
    {
        [JsonPropertyName("typ")]
        public string? Type { get; set; }
        [JsonPropertyName("val")]
        public string? Value { get; set; }
    }    
}

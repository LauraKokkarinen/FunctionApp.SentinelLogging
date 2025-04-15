namespace FunctionApp.SentinelLogging.Interfaces
{
    public interface IAuthService
    {
        Task<string> GetAccessTokenAsync(string resourceUrl);
    }
}

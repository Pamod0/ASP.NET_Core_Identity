namespace ASP.NET_Core_Identity.Models
{
    public class ApiResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public IEnumerable<string> Errors { get; set; } = Enumerable.Empty<string>();

        //public Dictionary<string, string> Errors { get; set; } = new();

    }

    public class RegistrationResult : ApiResponse
    {
        public string UserId { get; set; }
    }

    public class LoginResult : ApiResponse
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public DateTime Expiration { get; set; }
        public string? UserId { get; set; }
        public List<string>? Roles { get; set; }
        public bool? RequiresTwoFactor { get; set; }
        public IList<string>? Providers { get; set; }
    }
}

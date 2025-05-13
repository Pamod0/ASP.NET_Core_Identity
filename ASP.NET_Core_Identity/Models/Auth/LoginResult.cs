namespace ASP.NET_Core_Identity.Models.Auth
{
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

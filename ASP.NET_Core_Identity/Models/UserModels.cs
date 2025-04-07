namespace ASP.NET_Core_Identity.Models
{
    public class RegisterUser
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class LoginUser
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class UserRole
    {
        public string Email { get; set; }
        public string RoleName { get; set; }
    }

    public class AuthResponse
    {
        public string Token { get; set; }
        public DateTime Expiration { get; set; }
        public string UserId { get; set; }
        public List<string> Roles { get; set; }
    }

    public class EmailConfirmationRequest
    {
        public string UserId { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }
    }

    public class ResendConfirmationEmailRequest
    {
        public string Email { get; set; }
    }

    public class ClientAppSettings
    {
        public string BaseUrl { get; set; }
    }
}

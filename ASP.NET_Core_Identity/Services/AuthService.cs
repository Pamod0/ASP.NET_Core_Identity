using ASP.NET_Core_Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace ASP.NET_Core_Identity.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;
        private readonly IEmailService _emailService;
        private readonly IWebHostEnvironment _env;

        public AuthService(
            UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager, 
            IConfiguration config, 
            IEmailService emailService,
            IWebHostEnvironment env)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
            _emailService = emailService;
            _env = env;
        }

        public async Task<bool> RegisterUser(RegisterUser registerUser)
        {
            var identityUser = new IdentityUser
            {
                UserName = registerUser.Username,
                Email = registerUser.Email
            };

            var result = await _userManager.CreateAsync(identityUser, registerUser.Password);
            return result.Succeeded;
        }

        public async Task<bool> Login(LoginUser loginUser)
        {
            var identityUser = await _userManager.FindByEmailAsync(loginUser.Email);
            if (identityUser is null)
            {
                return false;
            }

            // Check if email is confirmed
            if (!await _userManager.IsEmailConfirmedAsync(identityUser))
            {
                return false;
            }

            return await _userManager.CheckPasswordAsync(identityUser, loginUser.Password);
        }

        public async Task<string> GenerateTokenString(LoginUser loginUser)
        {
            var identityUser = await _userManager.FindByEmailAsync(loginUser.Email);

            var roles = await _userManager.GetRolesAsync(identityUser);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, loginUser.Email),
                new Claim(ClaimTypes.NameIdentifier, identityUser.Id),
            };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("Jwt:Key").Value));

            var signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var securityToken = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(_config.GetValue<int>("Jwt:ExpireInMinutes")),
                issuer: _config.GetSection("Jwt:Issuer").Value,
                audience: _config.GetSection("Jwt:Audience").Value,
                signingCredentials: signingCred);

            string tokenString = new JwtSecurityTokenHandler().WriteToken(securityToken);
            return tokenString;
        }

        public async Task<bool> AssignRole(string email, string roleName)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return false;
            }

            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                await _roleManager.CreateAsync(new IdentityRole(roleName));
            }

            await _userManager.AddToRoleAsync(user, roleName);
            return true;
        }

        public async Task<bool> SendConfirmationEmailAsync(IdentityUser user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = $"{_config["ClientApp:BaseUrl"]}/confirm-email?userId={user.Id}&token={WebUtility.UrlEncode(token)}";

            string emailBody;
            if (_env.IsDevelopment())
            {
                emailBody = $"<p>Please confirm your email by <a href='{confirmationLink}'>clicking here</a></p>";
            }
            else
            {
                var template = await System.IO.File.ReadAllTextAsync("EmailTemplates/ConfirmEmail.html");
                emailBody = template.Replace("{confirmationLink}", confirmationLink);
            }

            await _emailService.SendEmailAsync(
                user.Email,
                "Confirm your email",
                emailBody);

            return true;
        }

        public async Task<bool> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return false;
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return result.Succeeded;
        }

        public async Task<bool> ResendConfirmationEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || await _userManager.IsEmailConfirmedAsync(user))
            {
                return false;
            }

            return await SendConfirmationEmailAsync(user);
            // Dev Note: Consider adding rate limiting to the resend confirmation email endpoint to prevent abuse.
        }
    }

    public interface IAuthService
    {
        Task<bool> RegisterUser(RegisterUser registerUser);
        Task<bool> Login(LoginUser loginUser);
        Task<string> GenerateTokenString(LoginUser loginUser);
        Task<bool> AssignRole(string email, string roleName);
        Task<bool> SendConfirmationEmailAsync(IdentityUser user);
        Task<bool> ConfirmEmailAsync(string userId, string token);
        Task<bool> ResendConfirmationEmailAsync(string email);
    }
}

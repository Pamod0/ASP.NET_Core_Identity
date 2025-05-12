using ASP.NET_Core_Identity.DTOs;
using ASP.NET_Core_Identity.Models;
using ASP.NET_Core_Identity.Services.Interfaces;
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
        private readonly IConfiguration _config;
        private readonly ILogger<AuthService> _logger;
        private readonly IWebHostEnvironment _env;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public AuthService(
            IConfiguration config,
            ILogger<AuthService> logger,
            IWebHostEnvironment env,
            UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService)
        {
            _config = config;
            _logger = logger;
            _env = env;
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
        }

        public async Task<RegistrationResult> RegisterUserAsync(RegisterUserDTO registerUser)
        {
            try
            {
                var user = new IdentityUser
                {
                    UserName = String.IsNullOrEmpty(registerUser.Username) ? registerUser.Email : registerUser.Username,
                    Email = registerUser.Email
                };

                var creationResult = await _userManager.CreateAsync(user, registerUser.Password);

                if (!creationResult.Succeeded)
                {
                    var errors = creationResult.Errors.Select(e => e.Description);
                    _logger.LogWarning("User creation failed: {Errors}", string.Join(", ", errors));

                    return new RegistrationResult
                    {
                        Success = false,
                        Message = AuthErrorMessages.RegistrationFailed,
                        Errors = errors
                    };
                }

                // Assign default role
                var roleResult = await _userManager.AddToRoleAsync(user, "User");
                if (!roleResult.Succeeded)
                {
                    _logger.LogWarning("Role assignment failed for user {UserId}", user.Id);
                    // Continue despite role assignment failure - user is still created
                }

                // Send confirmation email (fire and forget)
                _ = SendConfirmationEmailAsync(user);

                return new RegistrationResult
                {
                    Success = true,
                    Message = AuthSuccessMessages.RegistrationSuccess
                };
            }

            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during user registration for email {Email}", registerUser.Email);
                //return new RegistrationResult
                //{
                //    Success = false,
                //    Message = AuthErrorMessages.RegistrationFailed,
                //    Errors = new[] { ex.Message }
                //};
                throw; // Let the controller handle the exception
            }
        }

        public async Task<LoginResult> Login(LoginUser loginUser)
        {
            var user = await _userManager.FindByEmailAsync(loginUser.Email);
            if (user is null)
            {
                return new LoginResult { Success = false, Message = AuthErrorMessages.InvalidLoginAttempt };
            }

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                return new LoginResult { Success = false, Message = AuthErrorMessages.EmailNotConfirmed };
            }

            // Check if account is locked out
            if (await _userManager.IsLockedOutAsync(user))
            {
                return new LoginResult { Success = false, Message = AuthErrorMessages.AccountLockedOut };
            }

            // Check if 2FA is enabled
            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                // Generate and send 2FA token (if using email/SMS)
                // Or return response indicating 2FA is required
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email"); // or "Phone" or "Authenticator"

                return new LoginResult
                {
                    RequiresTwoFactor = true,
                    Providers = await _userManager.GetValidTwoFactorProvidersAsync(user),
                    Message = AuthErrorMessages.TwoFactorRequired
                };
            }

            var result = await _userManager.CheckPasswordAsync(user, loginUser.Password);

            if (!result)
            {
                // Increment failed login count
                await _userManager.AccessFailedAsync(user);
                return new LoginResult 
                { 
                    Success = false, 
                    Message = AuthErrorMessages.InvalidLoginAttempt,
                    Errors = [$"{AuthErrorMessages.InvalidLoginAttempt}"]
                };
            }
            else
            {
                // Reset failed count on successful login
                await _userManager.ResetAccessFailedCountAsync(user);
            }

            // Generate regular JWT token
            var tokenString = await GenerateTokenString(loginUser);
            var roles = await _userManager.GetRolesAsync(user);

            return new LoginResult
            {
                Success = true,
                Message = AuthSuccessMessages.LoginSuccess,
                Token = tokenString,
                Expiration = DateTime.Now.AddMinutes(_config.GetValue<int>("Jwt:ExpireInMinutes")),
                UserId = user.Id,
                Roles = [.. roles]
            };
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
            // Dev Note: Consider already confirmed accounts.
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

        public async Task<bool> SendPasswordResetEmailAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                // Don't reveal that the user doesn't exist or isn't confirmed
                return true;
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"{_config["ClientApp:BaseUrl"]}/auth/reset-password?email={WebUtility.UrlEncode(email)}&token={WebUtility.UrlEncode(token)}";

            var emailBody = _env.IsDevelopment()
                ? $"<p>Please reset your password by <a href='{resetLink}'>clicking here</a></p>"
                : (await System.IO.File.ReadAllTextAsync("EmailTemplates/ResetPassword.html"))
                    .Replace("{resetLink}", resetLink);

            await _emailService.SendEmailAsync(
                email,
                "Reset your password",
                emailBody);

            return true;
        }

        public async Task<bool> ResetPasswordAsync(string email, string token, string newPassword)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return false;
            }

            var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
            return result.Succeeded;
        }

        public async Task<TwoFactorResponse> EnableTwoFactorAuth(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new TwoFactorResponse { Success = false };
            }

            // Generate the shared key and QR code URI
            var sharedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(sharedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                sharedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var authenticatorUri = GenerateQrCodeUri(user.Email, sharedKey);

            // Generate recovery codes
            var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

            return new TwoFactorResponse
            {
                Success = true,
                SharedKey = sharedKey,
                AuthenticatorUri = authenticatorUri,
                RecoveryCodes = recoveryCodes.ToArray()
            };
        }

        public async Task<bool> VerifyTwoFactorCode(string email, string code, bool rememberDevice)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return false;
            }

            var isCodeValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                code);

            if (isCodeValid && rememberDevice)
            {
                // Manually set the remember device flag
                var userClaims = await _userManager.GetClaimsAsync(user);
                var rememberDeviceClaim = userClaims.FirstOrDefault(c => c.Type == "RememberDevice");
                if (rememberDeviceClaim != null)
                {
                    await _userManager.RemoveClaimAsync(user, rememberDeviceClaim);
                }
                await _userManager.AddClaimAsync(user, new Claim("RememberDevice", "true"));
            }

            return isCodeValid;
        }

        public async Task<bool> DisableTwoFactorAuth(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return false;
            }

            var result = await _userManager.SetTwoFactorEnabledAsync(user, false);
            return result.Succeeded;
        }

        public async Task<bool> VerifyRecoveryCode(string email, string code)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return false;
            }

            var result = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, code);
            return result.Succeeded;
        }

        private string GenerateQrCodeUri(string email, string sharedKey)
        {
            return string.Format(
                "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
                _config["Jwt:Issuer"],
                email,
                sharedKey);
        }
    }
}

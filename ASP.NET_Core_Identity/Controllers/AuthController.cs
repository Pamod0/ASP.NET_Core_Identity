using ASP.NET_Core_Identity.Models;
using ASP.NET_Core_Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace ASP.NET_Core_Identity.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _config;

        public AuthController(IAuthService authService, UserManager<IdentityUser> userManager, IConfiguration config)
        {
            _authService = authService;
            _userManager = userManager;
            _config = config;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var identityUser = new IdentityUser
            {
                UserName = registerUser.Email,
                Email = registerUser.Email
            };

            var result = await _userManager.CreateAsync(identityUser, registerUser.Password);
            if (!result.Succeeded)
            {
                var actualError = result.Errors;
                return BadRequest(new ApiResponse 
                { 
                    Success = false, Message = AuthErrorMessages.RegistrationFailed 
                });
            }

            // Assign default role
            await _userManager.AddToRoleAsync(identityUser, "User");

            // Send confirmation email
            await _authService.SendConfirmationEmailAsync(identityUser);

            return Ok(new 
            { 
                message = "User registered successfully. Please check your email for confirmation instructions." 
            });
        }

        [HttpPost("Login")]
        public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginUser loginUser)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(loginUser.Email);
            if (user == null)
            {
                return BadRequest(new AuthErrorResponse
                {
                    Error = new AuthErrorResponse.ErrorDetails
                    {
                        Message = AuthErrorMessages.InvalidLoginAttempt,
                        Code = "LoginFailed",
                        Status = 400
                    },
                    Status = 400,
                    StatusText = "Bad Request",
                    Message = AuthErrorMessages.InvalidLoginAttempt
                });
            }

            // Check password
            if (!await _userManager.CheckPasswordAsync(user, loginUser.Password))
            {
                return BadRequest(new AuthErrorResponse
                {
                    Error = new AuthErrorResponse.ErrorDetails
                    {
                        Message = AuthErrorMessages.InvalidLoginAttempt,
                        Code = "LoginFailed",
                        Status = 400
                    },
                    Status = 400,
                    StatusText = "Bad Request",
                    Message = AuthErrorMessages.InvalidLoginAttempt
                });
            }

            var loginResult = await _authService.Login(loginUser);
            if (!loginResult.Success)
            {
                return BadRequest(new AuthErrorResponse
                {
                    Error = new AuthErrorResponse.ErrorDetails
                    {
                        Message = loginResult.ErrorMessage,
                        Code = "LoginFailed",
                        Status = 400
                    },
                    Status = 400,
                    StatusText = "Bad Request",
                    Message = loginResult.ErrorMessage
                });
            }

            // Check if 2FA is enabled
            if (await _userManager.GetTwoFactorEnabledAsync(user))
            {
                // Generate and send 2FA token (if using email/SMS)
                // Or return response indicating 2FA is required
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email"); // or "Phone" or "Authenticator"

                return Ok(new
                {
                    RequiresTwoFactor = true,
                    Providers = await _userManager.GetValidTwoFactorProvidersAsync(user),
                    Message = AuthErrorMessages.TwoFactorRequired
                });
            }

            // Generate regular JWT token
            var tokenString = await _authService.GenerateTokenString(loginUser);
            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new AuthResponse
            {
                Token = tokenString,
                Expiration = DateTime.Now.AddMinutes(_config.GetValue<int>("Jwt:ExpireInMinutes")),
                UserId = user.Id,
                Roles = roles.ToList()
            });
        }

        [HttpPost("LoginWith2fa")]
        public async Task<ActionResult<AuthResponse>> LoginWith2fa([FromBody] Verify2FACodeRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return BadRequest("Invalid login attempt.");
            }

            // Verify 2FA code
            var isCodeValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                request.Code);

            if (!isCodeValid)
            {
                return BadRequest("Invalid verification code.");
            }

            // Generate JWT token
            var tokenString = await _authService.GenerateTokenString(new LoginUser
            {
                Email = request.Email,
                Password = "" // Not needed since we already verified the user
            });

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new AuthResponse
            {
                Token = tokenString,
                Expiration = DateTime.Now.AddMinutes(_config.GetValue<int>("Jwt:ExpireInMinutes")),
                UserId = user.Id,
                Roles = roles.ToList()
            });
        }

        [HttpPost("AssignRole")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AssignRole([FromBody] UserRole userRole)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _authService.AssignRole(userRole.Email, userRole.RoleName);
            if (!result)
            {
                return BadRequest("Role assignment failed.");
            }

            return Ok($"Role {userRole.RoleName} assigned to {userRole.Email} successfully.");
        }

        [HttpGet("UserInfo")]
        [Authorize]
        public async Task<IActionResult> GetUserInfo()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return NotFound();
            }

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new
            {
                user.Id,
                user.UserName,
                user.Email,
                user.EmailConfirmed,
                Roles = roles
            });
        }

        [HttpPost("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromBody] EmailConfirmationRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _authService.ConfirmEmailAsync(request.UserId, request.Token);
            if (!result)
            {
                return BadRequest("Email confirmation failed.");
            }

            return Ok(new ApiResponse {  Success = true, Message = "Email confirmed successfully." });
        }

        [HttpPost("ResendConfirmationEmail")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _authService.ResendConfirmationEmailAsync(request.Email);
            if (!result)
            {
                return BadRequest("Unable to resend confirmation email. The user may not exist or email may already be confirmed.");
            }

            return Ok("Confirmation email resent successfully.");
        }

        [HttpPost("ForgotPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            await _authService.SendPasswordResetEmailAsync(request.Email);

            // Always return success to prevent email enumeration attacks
            return Ok("If your email is registered, you'll receive a password reset link.");
        }

        [HttpPost("ResetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _authService.ResetPasswordAsync(
                request.Email,
                request.Token,
                request.NewPassword);

            if (!result)
            {
                return BadRequest("Password reset failed. The link may have expired or is invalid.");
            }

            return Ok("Password has been reset successfully.");
        }

        [HttpPost("Enable2FA")]
        [Authorize]
        public async Task<ActionResult<TwoFactorResponse>> EnableTwoFactorAuth()
        {
            var email = User.FindFirstValue(ClaimTypes.Email);
            var result = await _authService.EnableTwoFactorAuth(email);

            if (!result.Success)
            {
                return BadRequest("Failed to enable 2FA.");
            }

            return Ok(result);
        }

        [HttpPost("Verify2FACode")]
        [Authorize]
        public async Task<IActionResult> VerifyTwoFactorCode([FromBody] Verify2FACodeRequest request)
        {
            var email = User.FindFirstValue(ClaimTypes.Email);
            var isValid = await _authService.VerifyTwoFactorCode(email, request.Code, request.RememberDevice);

            if (!isValid)
            {
                return BadRequest("Invalid verification code.");
            }

            // Enable 2FA after successful verification
            var user = await _userManager.FindByEmailAsync(email);
            await _userManager.SetTwoFactorEnabledAsync(user, true);

            return Ok("Two-factor authentication has been enabled successfully.");
        }

        [HttpPost("Disable2FA")]
        [Authorize]
        public async Task<IActionResult> DisableTwoFactorAuth()
        {
            var email = User.FindFirstValue(ClaimTypes.Email);
            var success = await _authService.DisableTwoFactorAuth(email);

            if (!success)
            {
                return BadRequest("Failed to disable 2FA.");
            }

            return Ok("Two-factor authentication has been disabled.");
        }

        [HttpPost("VerifyRecoveryCode")]
        [AllowAnonymous]
        public async Task<ActionResult<AuthResponse>> VerifyRecoveryCode([FromBody] Verify2FACodeRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return BadRequest("Invalid request.");
            }

            var isValid = await _authService.VerifyRecoveryCode(request.Email, request.Code);
            if (!isValid)
            {
                return BadRequest("Invalid recovery code.");
            }

            // Generate JWT token
            var tokenString = await _authService.GenerateTokenString(new LoginUser
            {
                Email = request.Email,
                Password = "" // Not needed since we're using recovery code
            });

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new AuthResponse
            {
                Token = tokenString,
                Expiration = DateTime.Now.AddMinutes(_config.GetValue<int>("Jwt:ExpireInMinutes")),
                UserId = user.Id,
                Roles = roles.ToList()
            });
        }
    }
}

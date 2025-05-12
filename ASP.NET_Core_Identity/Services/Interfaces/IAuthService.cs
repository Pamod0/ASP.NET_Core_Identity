using ASP.NET_Core_Identity.DTOs;
using ASP.NET_Core_Identity.Models;
using Microsoft.AspNetCore.Identity;

namespace ASP.NET_Core_Identity.Services.Interfaces
{
    public interface IAuthService
    {
        Task<RegistrationResult> RegisterUserAsync(RegisterUserDTO registerUser);
        Task<LoginResult> Login(LoginUser loginUser);
        Task<string> GenerateTokenString(LoginUser loginUser);
        Task<bool> AssignRole(string email, string roleName);
        Task<bool> SendConfirmationEmailAsync(IdentityUser user);
        Task<bool> ConfirmEmailAsync(string userId, string token);
        Task<bool> ResendConfirmationEmailAsync(string email);
        Task<bool> SendPasswordResetEmailAsync(string email);
        Task<bool> ResetPasswordAsync(string email, string token, string newPassword);
        Task<TwoFactorResponse> EnableTwoFactorAuth(string email);
        Task<bool> VerifyTwoFactorCode(string email, string code, bool rememberDevice);
        Task<bool> DisableTwoFactorAuth(string email);
        Task<bool> VerifyRecoveryCode(string email, string code);
    }
}

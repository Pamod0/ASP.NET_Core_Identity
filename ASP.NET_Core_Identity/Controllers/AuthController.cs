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

            var result = await _authService.RegisterUser(registerUser);
            if (!result)
            {
                return BadRequest("User registration failed.");
            }

            // Assign default role
            await _authService.AssignRole(registerUser.Email, "User");

            return Ok("User registered successfully.");
        }

        [HttpPost("Login")]
        public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginUser loginUser)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (!await _authService.Login(loginUser))
            {
                return BadRequest("Invalid login attempt.");
            }

            var tokenString = await _authService.GenerateTokenString(loginUser);
            var user = await _userManager.FindByEmailAsync(loginUser.Email);
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
    }
}

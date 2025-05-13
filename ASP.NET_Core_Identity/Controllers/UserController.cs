using ASP.NET_Core_Identity.DTOs;
using ASP.NET_Core_Identity.Models;
using ASP.NET_Core_Identity.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ASP.NET_Core_Identity.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IUserService _userService;

        public UserController(
            ILogger<UserController> logger,
            UserManager<IdentityUser> userManager,
            IUserService userService)
        {
            _logger = logger;
            _userManager = userManager;
            _userService = userService;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDTO>>> GetAll([FromQuery] PagedRequest request)
        {
            try
            {
                var result = await _userService.GetAllUsersAsync(request);
                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred while retrieving users.");
                return StatusCode(500, "Internal server error");
            }
        }
    }
}

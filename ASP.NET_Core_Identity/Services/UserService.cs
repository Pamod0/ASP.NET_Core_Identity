using ASP.NET_Core_Identity.DTOs;
using ASP.NET_Core_Identity.Models;
using ASP.NET_Core_Identity.Services.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ASP.NET_Core_Identity.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<IdentityUser> _userManager;

        public UserService(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<PagedResponse<IEnumerable<UserDTO>>> GetAllUsersAsync(PagedRequest request)
        {
            if (request.Page < 1) request.Page = 1;
            if (request.PageSize < 1) request.PageSize = 10; // Default to 10 if invalid

            var query = _userManager.Users
                .OrderBy(u => u.Email) // Order by Name (best practice for consistency)
                .Select(u => new UserDTO
                {
                    Id = u.Id,
                    UserName = u.UserName,
                    Email = u.Email,
                    EmailConfirmed = u.EmailConfirmed,
                    PhoneNumber = u.PhoneNumber,
                    PhoneNumberConfirmed = u.PhoneNumberConfirmed,
                    TwoFactorEnabled = u.TwoFactorEnabled,
                    LockoutEnd = u.LockoutEnd,
                    LockoutEnabled = u.LockoutEnabled,
                    AccessFailedCount = u.AccessFailedCount
                });

            if (!string.IsNullOrEmpty(request.SearchText) && request.ExactMatch)
            {
                var exactRecord = await query
                    .FirstOrDefaultAsync(u => u.Email == request.SearchText);

                if (exactRecord != null)
                {
                    return new PagedResponse<IEnumerable<UserDTO>>(1, 1, 1, new List<UserDTO> { exactRecord });
                }

                return new PagedResponse<IEnumerable<UserDTO>>(1, 1, 0, new List<UserDTO>()); // No record found
            }

            // Apply search filter for partial matches
            if (!string.IsNullOrEmpty(request.SearchText))
            {
                query = query.Where(u => u.Email.Contains(request.SearchText)); // Case-sensitive search
            }

            var totalRecords = await query.CountAsync(); // Get total user count
            var users = await query
                .Skip((request.Page - 1) * request.PageSize)
                .Take(request.PageSize)
                .ToListAsync(); // Fetch paginated results

            return new PagedResponse<IEnumerable<UserDTO>>(request.Page, request.PageSize, totalRecords, users);
        }
    }
}

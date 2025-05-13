using ASP.NET_Core_Identity.DTOs;
using ASP.NET_Core_Identity.Models;

namespace ASP.NET_Core_Identity.Services.Interfaces
{
    public interface IUserService
    {
        Task<PagedResponse<IEnumerable<UserDTO>>> GetAllUsersAsync(PagedRequest request);
    }
}

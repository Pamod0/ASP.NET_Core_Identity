using System.ComponentModel.DataAnnotations;

namespace ASP.NET_Core_Identity.DTOs
{
    public class RegisterUserDTO
    {
        public string? Username { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}

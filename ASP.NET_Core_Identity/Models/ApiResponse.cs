namespace ASP.NET_Core_Identity.Models
{
    public class ApiResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public IEnumerable<string> Errors { get; set; } = Enumerable.Empty<string>();

    }
}

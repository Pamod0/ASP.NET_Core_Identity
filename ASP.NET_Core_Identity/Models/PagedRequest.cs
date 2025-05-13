namespace ASP.NET_Core_Identity.Models
{
    public class PagedRequest
    {
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 10;
        public string? SearchText { get; set; } = String.Empty;
        public bool ExactMatch { get; set; } = false;
    }
}

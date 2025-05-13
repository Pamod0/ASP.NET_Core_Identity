namespace ASP.NET_Core_Identity.Models
{
    public class PagedResponse<T>
    {
        public int Page { get; set; }
        public int PageSize { get; set; }
        public int TotalRecords { get; set; }
        public int TotalPages => (int)Math.Ceiling((double)TotalRecords / PageSize);
        public T Data { get; set; }

        public PagedResponse(int page, int pageSize, int totalRecords, T data)
        {
            Page = page;
            PageSize = pageSize;
            TotalRecords = totalRecords;
            Data = data;
        }
    }
}

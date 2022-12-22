using System.ComponentModel.DataAnnotations;

namespace Webadvert_Web.Models.Accounts
{
    public class ConfirmModel
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Code is required.")]
        public string Code { get; set; }
    }
}

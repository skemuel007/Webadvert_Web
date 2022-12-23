using System.ComponentModel.DataAnnotations;
using System.Xml.Linq;

namespace Webadvert_Web.Models.Accounts
{
    public class ResetPassword { 

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }
    }

    public class ConfirmPasswordReset
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [StringLength(6, ErrorMessage = "Password must be at least 6 characters long")]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwrod and its confirmation does not match")]
        public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "Token is required.")]
        [Display(Name = "Token")]
        public string ResetToken { get; set; }
    }
}

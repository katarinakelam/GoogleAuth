using Google.Authenticator;
using GoogleAuthenticatorTryTwo.ViewModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using System.Data.SqlClient;
using System.Collections;
using System.Configuration;
using System.Xml.Linq;
using System.Security.Cryptography;

namespace GoogleAuthenticatorTryTwo.Controllers
{
    public class HomeController : Controller
    {
        private const string key = "8f3!hjdfnjh"; //10-12 znakova
        private SqlConnection conn = new SqlConnection(ConfigurationManager.ConnectionStrings["connect"].ToString());

        public string CreateSalt(int saltSize)
        {
            var random = new RNGCryptoServiceProvider();
            var buffer = new byte[saltSize];
            random.GetBytes(buffer);
            string salt = Convert.ToBase64String(buffer);

            return salt;
        }

        public string GenerateHash(string rawPassword, string salt)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(rawPassword + salt);
            SHA256Managed hash = new SHA256Managed();
            byte[] hashPassword = hash.ComputeHash(bytes);
            string password = Convert.ToBase64String(hashPassword);

            return password;
        }

        public ActionResult Login()
        {
            return View();
        }

        public ActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Login(LoginModel login)
        {
            string message = "";
            bool status = false;
            conn.Open();

            try
            {
                string saltQuery = "SELECT [Salt] FROM [User] WHERE [Username]='" + login.Username + "'";
                SqlCommand saltcmd = new SqlCommand(saltQuery, conn);
                SqlDataReader reader = saltcmd.ExecuteReader();
                string salt="";
                while (reader.Read())
                {
                    salt = reader["Salt"].ToString();
                }

                string userQuery = "SELECT * FROM [User] WHERE [Username]='" + login.Username + "' AND [Password]='" + GenerateHash(login.Password, salt) + "'";
                SqlCommand cmd = new SqlCommand(userQuery, conn);
                string output = cmd.ExecuteScalar().ToString();

                //Check Password and username here from database
                if (output != "0")
                {
                    status = true;
                    message = "2FA Verification";
                    Session["Username"] = login.Username;

                    TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
                    string UserUniqueKey = GenerateHash(login.Password, salt) + key;
                    Session["UserUniqueKey"] = UserUniqueKey;
                    var SetupInfo = tfa.GenerateSetupCode("2FA Demonstrative Application", login.Username, UserUniqueKey, 300, 300);
                    ViewBag.BarcodeImageUrl = SetupInfo.QrCodeSetupImageUrl;
                    ViewBag.SetupCode = SetupInfo.ManualEntryKey;
                }
                else
                {
                    message = "Invalid credentials!";
                }
            }
            catch
            {
               return RedirectToAction("Register", "Home");

            }
                ViewBag.Message = message;
                ViewBag.Status = status;
            
            conn.Close();

            return View();
        }

        public ActionResult MyProfile()
        {
            if (Session["Username"] == null || Session["IsValid2FA"] == null || !(bool)Session["IsValid2FA"])
            {
                return RedirectToAction("Login");
            }

            conn.Open();
            string saltQuery = "SELECT * FROM [User] WHERE [Username]='" + Session["Username"] + "'";
            SqlCommand saltcmd = new SqlCommand(saltQuery, conn);
            SqlDataReader reader = saltcmd.ExecuteReader();
            string name = "";
            string surname = "";
            while (reader.Read())
            {
            name = reader["Name"].ToString();
            surname = reader["Surname"].ToString();
            }

            ViewBag.Message = "Welcome " + name + " " + surname;

            conn.Close();
            return View();
        }

        public ActionResult Verify2FA()
        {
            var token = Request["passcode"];
            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
            string UserUniqueKey = Session["UserUniqueKey"].ToString();
            bool isValid = tfa.ValidateTwoFactorPIN(UserUniqueKey, token);
            if (isValid)
            {
                Session["IsValid2FA"] = true;
                return RedirectToAction("MyProfile", "Home");
            }

            return RedirectToAction("Login", "Home");
        }

        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            Session.Abandon();
            return RedirectToAction("Login", "Home");
        }

        [HttpPost]
        public ActionResult Register(RegisterModel register)
        {
            string message = "";
            bool status = false;
            conn.Open();
            string findUserQuery = "SELECT * FROM [User] WHERE [Username]='" + register.Username + "'";
            SqlCommand cmd = new SqlCommand(findUserQuery, conn);
            string output;
            try
            {
                output = cmd.ExecuteScalar().ToString();
            }
            catch
            {
                output = "0";
            }
           
            //Check Password and username here from database
            if (output != "0")
            {
                message = "User under that username already exists, please select another one";
            }
            else
            {
                if (register.Password == register.RetypedPassword)
                {
                    string salt = CreateSalt(10);
                    string addUserQuery = "INSERT INTO [User] ([Name], [Surname], [Username], [Password], [Salt]) VALUES ('" + register.Name + "', '" + register.Surname + "', '" + register.Username + "', '" + GenerateHash(register.Password, salt) + "','" + salt + "')";
                    SqlCommand addCmd = new SqlCommand(addUserQuery, conn);
                    string addOutput = addCmd.ExecuteNonQuery().ToString();
                    if (addOutput != null)
                    {
                        message = "Registration successful " + register.Username + "!";
                    }
                    else
                    {
                        message = "Registration unsuccessful!";
                    }  
                }
                else
                {
                    message = "Wrongly retyped password!";
                }
                status = true;
            }

            ViewBag.Message = message;
            ViewBag.Status = status;
            conn.Close();

            return View();
        }

        public ActionResult RedirectingToLogin()
        {
            return RedirectToAction("Login", "Home");
        }

        public ActionResult RedirectingToRegister()
        {
            return RedirectToAction("Register", "Home");
        }

    }
}
using JwtAuthDemo.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.DataHandler.Encoder;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Web.Http;

namespace JwtAuthDemo.Controllers
{
    /// <summary>
    /// 認證控制器
    /// </summary>
    [AllowAnonymous]
    public class AuthController : ApiController
    {
        /// <summary>
        /// 登入並取得 Token
        /// </summary>
        /// <param name="login">傳入登入帳密</param>
        /// <returns></returns>
        [HttpPost]
        public IHttpActionResult Login(LoginModel login)
        {
            if(login.Password == "1234")
            {
                var issuer = ConfigurationManager.AppSettings["Issuer"];
                var secret = ConfigurationManager.AppSettings["SignKey"];

                var token = GenerateToken(login.Username, issuer, secret);
                return Ok(new
                {
                    Token = token
                });
            }
            return Unauthorized();
        }

        private static string GenerateToken(string username, string issuer, string secret)
        {
            var symmetricKey = Convert.FromBase64String(secret);
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, username),
                }),
                Issuer = issuer,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(20),

                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(symmetricKey),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(securityToken);

            return token;
        }
    }
}
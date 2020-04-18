using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using myop.Models;

namespace myop.Controllers
{
    [Route("op/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        string CLIENT_ID;
        string RESPONSE_TYPE;
        string REDIRECT_URI;
        string SCOPE;
        string STATE;
        string NONCE;

        public AuthController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: op/auth
        [HttpGet]
        [Authorize]
        public async Task<ActionResult> doGet()
        {
            CLIENT_ID = HttpContext.Request.Query["client_id"].ToString();
            RESPONSE_TYPE = HttpContext.Request.Query["response_type"].ToString();
            REDIRECT_URI = HttpContext.Request.Query["redirect_uri"].ToString();
            SCOPE = HttpContext.Request.Query["scope"].ToString();
            STATE = HttpContext.Request.Query["state"].ToString();
            NONCE = HttpContext.Request.Query["nonce"].ToString();

            var client = await _context.Clients.FindAsync(CLIENT_ID);
            if (client == null) {
                return Redirect(REDIRECT_URI + "#error=unauthorized_client");
            }
            if (client.RedirectUris != System.Web.HttpUtility.UrlDecode(REDIRECT_URI)) {
                return Redirect(REDIRECT_URI + "#error=invalid_request");
            }
            string random = Guid.NewGuid().ToString("N").ToUpper();
            string refresh = Guid.NewGuid().ToString("N").ToUpper();
            string param = "&state="+STATE;
            if (RESPONSE_TYPE == "code") {
                if (client.GrantTypes != "authorization_code") {
                    return Redirect(REDIRECT_URI + "#error=unsupported_response_type");
                }
                var code = new Code {CodeId = random, UserId = User.Identity.Name, Nonce =HttpContext.Request.QueryString.Value.Substring(1), Iat=DateTime.Now};
                _context.Add(code);
                param = "?code=" + random + param;
            } else if (RESPONSE_TYPE == "token") {
                if (client.GrantTypes != "implicit") {
                    return Redirect(REDIRECT_URI + "#error=unsupported_response_type");
                }
                var access_token = await _context.Tokens.FindAsync(User.Identity.Name);
                if (access_token != null) {
                    _context.Tokens.Remove(access_token);
                    await _context.SaveChangesAsync();
                }
                access_token = new Token {UserId = User.Identity.Name, AccessToken = random, Scope = SCOPE, Iat=DateTime.Now};
                _context.Add(access_token);
                param = "#access_token=" + random + "&token_type=bearer" + param;
            } else if (RESPONSE_TYPE == "id_token") {
                if (client.GrantTypes != "implicit") {
                    return Redirect(REDIRECT_URI + "#error=unsupported_response_type");
                }
                var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, User.Identity.Name),
                new Claim(JwtRegisteredClaimNames.Nonce, NONCE)
                };
                var pemStr = System.IO.File.ReadAllText(@"./private.pem");
                var base64 = pemStr
                .Replace("-----BEGIN RSA PRIVATE KEY-----", string.Empty)
                .Replace("-----END RSA PRIVATE KEY-----", string.Empty)
                .Replace("\r\n", string.Empty)
                .Replace("\n", string.Empty);
                var der = Convert.FromBase64String(base64);
                var rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(der, out _);
                var key = new RsaSecurityKey(rsa);
                key.KeyId = "testkey";
                var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
                var jwtHeader = new JwtHeader(creds);
                var jwtPayload = new JwtPayload(
                    issuer: "https://raspberry.pi/op",
                    audience: CLIENT_ID,
                    claims: claims,
                    notBefore: DateTime.Now,
                    expires: DateTime.Now.AddMinutes(600),
                    issuedAt: DateTime.Now
                );
                var jwt = new JwtSecurityToken(jwtHeader, jwtPayload);
                var id_token = new JwtSecurityTokenHandler().WriteToken(jwt);
                param = "#id_token=" + id_token + param;
            } else if (RESPONSE_TYPE == "token id_token") {
                if (client.GrantTypes != "implicit") {
                    return Redirect(REDIRECT_URI + "#error=unsupported_response_type");
                }
                var access_token = await _context.Tokens.FindAsync(User.Identity.Name);
                if (access_token != null) {
                    _context.Tokens.Remove(access_token);
                    await _context.SaveChangesAsync();
                }
                access_token = new Token {UserId = User.Identity.Name, AccessToken = random, Scope = SCOPE, Iat=DateTime.Now};
                _context.Add(access_token);
                SHA256Managed hashstring = new SHA256Managed();
                byte[] bytes = Encoding.Default.GetBytes(random);
                byte[] hash = hashstring.ComputeHash(bytes);
                Byte[] sixteen_bytes = new Byte[16];
                Array.Copy(hash, sixteen_bytes, 16);
                var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, User.Identity.Name),
                new Claim(JwtRegisteredClaimNames.AtHash, Convert.ToBase64String(sixteen_bytes).Trim('=')),
                new Claim(JwtRegisteredClaimNames.Nonce, NONCE)
                };
                var pemStr = System.IO.File.ReadAllText(@"./private.pem");
                var base64 = pemStr
                .Replace("-----BEGIN RSA PRIVATE KEY-----", string.Empty)
                .Replace("-----END RSA PRIVATE KEY-----", string.Empty)
                .Replace("\r\n", string.Empty)
                .Replace("\n", string.Empty);
                var der = Convert.FromBase64String(base64);
                var rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(der, out _);
                var key = new RsaSecurityKey(rsa);
                key.KeyId = "testkey";
                var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
                var jwtHeader = new JwtHeader(creds);
                var jwtPayload = new JwtPayload(
                    issuer: "https://raspberry.pi/op",
                    audience: CLIENT_ID,
                    claims: claims,
                    notBefore: DateTime.Now,
                    expires: DateTime.Now.AddMinutes(600),
                    issuedAt: DateTime.Now
                );
                var jwt = new JwtSecurityToken(jwtHeader, jwtPayload);
                var id_token = new JwtSecurityTokenHandler().WriteToken(jwt);
                param = "#access_token=" + random + "&token_type=bearer&id_token=" + id_token + param;
            } else {
                return Redirect(REDIRECT_URI + "#error=unsupported_response_type");
            }
            await _context.SaveChangesAsync();
            return Redirect(REDIRECT_URI + param);
        }
    }
}

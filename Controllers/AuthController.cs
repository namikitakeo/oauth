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
using Microsoft.Extensions.Options;
using myop.Models;

namespace myop.Controllers
{
    [Route("op/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly AppSettings _appSettings;
        string CLIENT_ID;
        string RESPONSE_TYPE;
        string REDIRECT_URI;
        string SCOPE;
        string STATE;
        string NONCE;
        string AT_HASH;
        public AuthController(ApplicationDbContext context, IOptions<AppSettings> optionsAccessor)
        {
            _context = context;
            _appSettings = optionsAccessor.Value;
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
                return Redirect("#error=unauthorized_client&error_description=client authentication failed.");
            }
            if (client.RedirectUris != System.Web.HttpUtility.UrlDecode(REDIRECT_URI)) {
                return Redirect("#error=invalid_request&error_description=redirect_uri is not valid.");
            }
            if (STATE == null) {
                return Redirect(REDIRECT_URI + "#error=invalid_request&error_description=state is not valid.");
            }
            string random = Guid.NewGuid().ToString("N").ToUpper();
            string refresh = Guid.NewGuid().ToString("N").ToUpper();
            string param = "&state="+STATE;
            if (RESPONSE_TYPE == "code") {
                if (client.GrantTypes != "authorization_code") {
                    return Redirect(REDIRECT_URI + "#error=unsupported_response_type&error_description=the response_type value is not supported.");
                }
                var code = new Code {CodeId = random, UserId = User.Identity.Name, ClientId = CLIENT_ID, Nonce = NONCE, Iat=DateTime.Now};
                _context.Add(code);
                await _context.SaveChangesAsync();
                param = "?code=" + random + param;
            } else if (RESPONSE_TYPE == "token") {
                if (client.GrantTypes != "implicit") {
                    return Redirect(REDIRECT_URI + "#error=unsupported_response_type&error_description=the response_type value is not supported.");
                }
                var access_token = await _context.Tokens.FindAsync(User.Identity.Name);
                if (access_token != null) {
                    _context.Tokens.Remove(access_token);
                    await _context.SaveChangesAsync();
                }
                access_token = new Token {UserId = User.Identity.Name, AccessToken = random, ClientId = CLIENT_ID, Scope = SCOPE, Iat=DateTime.Now};
                _context.Add(access_token);
                await _context.SaveChangesAsync();
                param = "#access_token=" + random + "&token_type=bearer" + param;
            } else if (RESPONSE_TYPE == "id_token") {
                if (client.GrantTypes != "implicit") {
                    return Redirect(REDIRECT_URI + "#error=unsupported_response_type&error_description=the response_type value is not supported.");
                }
                var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, User.Identity.Name),
                new Claim(JwtRegisteredClaimNames.Nonce, NONCE)
                };
                var id_token = Util.GetIdToken(claims, CLIENT_ID, _appSettings.Myop.BaseUrl);
                param = "#id_token=" + id_token + param;
            } else if (RESPONSE_TYPE == "token id_token" || RESPONSE_TYPE == "id_token token") {
                if (client.GrantTypes != "implicit") {
                    return Redirect(REDIRECT_URI + "#error=unsupported_response_type&error_description=the response_type value is not supported.");
                }
                var access_token = await _context.Tokens.FindAsync(User.Identity.Name);
                if (access_token != null) {
                    _context.Tokens.Remove(access_token);
                    await _context.SaveChangesAsync();
                }
                access_token = new Token {UserId = User.Identity.Name, AccessToken = random, ClientId = CLIENT_ID, Scope = SCOPE, Iat=DateTime.Now};
                _context.Add(access_token);
                await _context.SaveChangesAsync();
                AT_HASH = Util.GetAtHash(random);
                var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, User.Identity.Name),
                new Claim(JwtRegisteredClaimNames.AtHash, AT_HASH),
                new Claim(JwtRegisteredClaimNames.Nonce, NONCE)
                };
                var id_token = Util.GetIdToken(claims, CLIENT_ID, _appSettings.Myop.BaseUrl);
                param = "#access_token=" + random + "&token_type=bearer&id_token=" + id_token + param;
            } else {
                return Redirect(REDIRECT_URI + "#error=unsupported_response_type&error_description=the response_type value is not supported.");
            }
            return Redirect(REDIRECT_URI + param);
        }
    }
}

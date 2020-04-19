using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using myop.Models;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace myop.Controllers
{
    public class AccessToken
    {
        public string access_token { get; set; }
        public int? expires_in { get; set; }
        public string refresh_token { get; set; }
        public int? refresh_token_expires_in { get; set; }
        public string token_type { get; set; }
        public string id_token { get; set; }
        public string scope { get; set; }
        public string error { get; set; }
        public string error_description { get; set; }
    }

    [Route("op/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        string CLIENT_ID;
        string CLIENT_SECRET;
        string GRANT_TYPE;
        string SCOPE;
        string USERNAME;
        string PASSWORD;
        string CODE;
        string REFRESH_TOKEN;
        string NONCE;
        public TokenController(ApplicationDbContext context)
        {
            _context = context;
        }
        // POST: op/token
        [HttpPost]
        public async Task<ActionResult<AccessToken>> doPost()
        {
            string body = await new StreamReader(HttpContext.Request.Body).ReadToEndAsync();
            string[] p =  body.Split('&');
            for (int i=0; i<p.Length; i++){
                string[] values =  p[i].Split('=');
                switch(values[0])
                {
                    case "client_id":CLIENT_ID=values[1];break;
                    case "client_secret":CLIENT_SECRET=values[1];break;
                    case "grant_type":GRANT_TYPE=values[1];break;
                    case "scope":SCOPE=values[1];break;
                    case "username":USERNAME=values[1];break;
                    case "password":PASSWORD=values[1];break;
                    case "code":CODE=values[1];break;
                    case "refresh_token":REFRESH_TOKEN=values[1];break;
                }
            }
            var client = await _context.Clients.FindAsync(CLIENT_ID);
            if (client == null) {
                return new AccessToken {error = "unauthorized_client", error_description="client authentication failed."};
            }
            string idtoken = null;
            string random = Guid.NewGuid().ToString("N").ToUpper();
            string refresh = Guid.NewGuid().ToString("N").ToUpper();
            if (GRANT_TYPE == "refresh_token") {
                if (client.GrantTypes == "implicit" || client.GrantTypes == "client_credentials") {
                    return new AccessToken {error = "unsupported_response_type", error_description="the response_type value is not supported."};
                }
                var refresh_token = _context.Tokens.FirstOrDefault(r => r.RefreshToken == REFRESH_TOKEN);
                if (refresh_token == null) {
                    return new AccessToken {error = "unsupported_response_type", error_description="the response_type value is not supported."};
                } else {
                    if (CLIENT_ID != refresh_token.ClientId) return new AccessToken {error = "invalid_request", error_description = "client_id is not valid."};
                    int unixTimestamp = (int)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                    int iat = (int)(refresh_token.Iat.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                    if (unixTimestamp - iat > 3600) {
                        return new AccessToken {error = "access_denied", error_description="the refresh_token is not valid."};
                    }
                    USERNAME = refresh_token.UserId;
                    SCOPE = refresh_token.Scope;
                }
            } else {
                if (client.GrantTypes != GRANT_TYPE) {
                    return new AccessToken {error = "unsupported_response_type", error_description="the response_type value is not supported."};
                }
                if (client.GrantTypes == "client_credentials") USERNAME="admin";
                if (client.GrantTypes == "password") {
                    var user = _context.Users.FirstOrDefault(u => u.UserName == USERNAME);
                    if (user == null ) {
                        return new AccessToken {error = "access_denied", error_description="user authentication failed."};
                    }
                    byte[] buffer4;
                    byte[] src = Convert.FromBase64String(user.PasswordHash);
                    byte[] dst = new byte[0x10];
                    Buffer.BlockCopy(src, 0x0D, dst, 0, 0x10);
                    byte[] buffer3 = new byte[0x20];
                    Buffer.BlockCopy(src, 0x1D, buffer3, 0, 0x20);
                    using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(PASSWORD, dst, 0x2710, HashAlgorithmName.SHA256))
                    {
                        buffer4 = bytes.GetBytes(0x20);
                    }
                    if (!Util.ByteArraysEqual(buffer3, buffer4)) {
                        return new AccessToken {error = "access_denied", error_description="user authentication failed."};
                    }
                }
                if (client.GrantTypes == "authorization_code") {
                    var code = await _context.Codes.FindAsync(CODE);
                    if (code == null) {
                        return new AccessToken {error = "invalid_request", error_description="the code is not valid."};
                    }
                    USERNAME=code.UserId;
                    NONCE=code.Nonce;
                    _context.Codes.Remove(code);
                    await _context.SaveChangesAsync();
                    if (CLIENT_ID != code.ClientId) return new AccessToken {error = "invalid_request", error_description = "client_id is not valid."};
                    if (NONCE == null) return new AccessToken {error = "invalid_request", error_description = "nonce is not valid."};
                    var claims = new[] {
                    new Claim(JwtRegisteredClaimNames.Sub, USERNAME),
                    new Claim(JwtRegisteredClaimNames.Nonce, NONCE)
                    };
                    idtoken=Util.GetIdToken(claims, CLIENT_ID);
                }
                string t="openid";
                if (SCOPE != null) {
                    string[] s =  SCOPE.Split(' ');
                    for (int j=0; j<s.Length; j++){
                        if (s[j]!="openid" && client.AllowedScope.Contains(s[j])) t=t+" "+s[j];
                    }
                }
                SCOPE=t;
            }
            if (client.AccessType == "confidential") {
                    if (client.ClientSecret != CLIENT_SECRET) {
                        return new AccessToken {error = "invalid_request", error_description="client authentication failed."};
                    }
            } else if (client.AccessType == "public") {
                if (client.GrantTypes == "client_credentials") {
                    return new AccessToken {error = "invalid_request", error_description="client authentication failed."};
                }
                if (CLIENT_SECRET != null) {
                    return new AccessToken {error = "invalid_request", error_description="client authentication failed."};
                }
            } else {
                return new AccessToken {error = "invalid_request", error_description="client authentication failed."};
            }
            var token = await _context.Tokens.FindAsync(USERNAME);
            if (token != null) {
                _context.Tokens.Remove(token);
                await _context.SaveChangesAsync();
            }
            token = new Token {UserId = USERNAME, AccessToken = random, ClientId = CLIENT_ID, RefreshToken=refresh, Scope = SCOPE, Iat=DateTime.Now};
            _context.Add(token);
            await _context.SaveChangesAsync();
            if (client.GrantTypes == "client_credentials") return new AccessToken {access_token = random, expires_in=60, token_type="bearer", scope = SCOPE};
            else return new AccessToken {access_token = random, expires_in=60, refresh_token = refresh, refresh_token_expires_in= 3600, id_token = idtoken, token_type="bearer", scope = SCOPE};
        }
    }
}

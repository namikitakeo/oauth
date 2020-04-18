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
        private bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (a == null && b == null)
            {
                return true;
            }
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }
            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= (a[i] == b[i]);
            }
            return areSame;
        }
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
                return new AccessToken {error = "unauthorized_client"};
            }
            string idtoken = null;
            string random = Guid.NewGuid().ToString("N").ToUpper();
            string refresh = Guid.NewGuid().ToString("N").ToUpper();
            if (GRANT_TYPE == "refresh_token") {
                if (client.GrantTypes == "implicit" || client.GrantTypes == "client_credentials") {
                    return new AccessToken {error = "invalid_request"};
                }
                var refresh_token = _context.Tokens.FirstOrDefault(r => r.RefreshToken == REFRESH_TOKEN);
                if (refresh_token == null) {
                    return new AccessToken {error = "unsupported_response_type"};
                } else {
                    int unixTimestamp = (int)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                    int iat = (int)(refresh_token.Iat.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                    if (unixTimestamp - iat > 3600) {
                        return new AccessToken {error = "unsupported_response_type"};                        
                    }
                    USERNAME = refresh_token.UserId;
                    SCOPE = refresh_token.Scope;
                }
            } else {
                if (client.GrantTypes != GRANT_TYPE) {
                    return new AccessToken {error = "unsupported_response_type"};
                }
                if (client.GrantTypes == "client_credentials") USERNAME="admin";
                if (client.GrantTypes == "password") {
                    var user = _context.Users.FirstOrDefault(u => u.UserName == USERNAME);
                    if (user == null ) {
                        return new AccessToken {error = "unsupported_response_type"};
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
                    if (!ByteArraysEqual(buffer3, buffer4)) {
                        return new AccessToken {error = "unsupported_response_type"};
                    }
                }
                if (client.GrantTypes == "authorization_code") {
                    var code = await _context.Codes.FindAsync(CODE);
                    if (code == null) {
                        return new AccessToken {error = "invalid_request"};
                    }
                    USERNAME=code.UserId;
                    NONCE=code.Nonce;
                    _context.Codes.Remove(code);
                    await _context.SaveChangesAsync();
                    string[] q =  NONCE.Split('&');
                    for (int i=0; i<q.Length; i++){
                        string[] values =  q[i].Split('=');
                        switch(values[0])
                        {
                            case "nonce":NONCE=values[1];break;
                        }
                    }
                    SHA256Managed hashstring = new SHA256Managed();
                    byte[] bytes = Encoding.Default.GetBytes(random);
                    byte[] hash = hashstring.ComputeHash(bytes);
                    Byte[] sixteen_bytes = new Byte[16];
                    Array.Copy(hash, sixteen_bytes, 16);
                    var claims = new[] {
                    new Claim(JwtRegisteredClaimNames.Sub, USERNAME),
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
                    idtoken = new JwtSecurityTokenHandler().WriteToken(jwt);
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
                        return new AccessToken {error = "invalid_request"};
                    }
            } else if (client.AccessType == "public") {
                if (client.GrantTypes == "client_credentials") {
                    return new AccessToken {error = "invalid_request"};
                }
                if (CLIENT_SECRET != null) {
                    return new AccessToken {error = "invalid_request"};
                }
            } else {
                return new AccessToken {error = "invalid_request"};
            }
            var token = await _context.Tokens.FindAsync(USERNAME);
            if (token != null) {
                _context.Tokens.Remove(token);
                await _context.SaveChangesAsync();
            }
            token=new Token {UserId = USERNAME, AccessToken = random, RefreshToken=refresh, Scope = SCOPE, Iat=DateTime.Now};
            _context.Add(token);
            await _context.SaveChangesAsync();
            if (client.GrantTypes == "client_credentials") refresh = null;
            AccessToken access_token=new AccessToken {access_token = random, expires_in=60, refresh_token = refresh, refresh_token_expires_in=3600, id_token = idtoken, token_type="bearer", scope = SCOPE};
            return access_token;
        }
    }
}

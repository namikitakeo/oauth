using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using myop.Models;

namespace myop.Controllers
{
    public class Introspect
    {
        public bool active { get; set; }
        public string scope { get; set; }
        public int? exp { get; set; }
        public int? iat { get; set; }
        public string sub { get; set; }
        public string aud { get; set; }
        public string iss { get; set; }
    }

    [Route("op/[controller]")]
    [ApiController]
    public class IntrospectController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly AppSettings _appSettings;
        string CLIENT_ID;
        string CLIENT_SECRET;
        string TOKEN;

        public IntrospectController(ApplicationDbContext context, IOptions<AppSettings> optionsAccessor)
        {
            _context = context;
            _appSettings = optionsAccessor.Value;
        }

        // POST: op/introspect
        [HttpPost]
        public async Task<ActionResult<Introspect>> doPost()
        {
            string body = await new StreamReader(HttpContext.Request.Body).ReadToEndAsync();
            string[] p =  body.Split('&');
            for (int i=0; i<p.Length; i++){
                string[] values =  p[i].Split('=');
                switch(values[0])
                {
                    case "client_id":CLIENT_ID=values[1];break;
                    case "client_secret":CLIENT_SECRET=values[1];break;
                    case "token":TOKEN=values[1];break;
                }
            }
            string ISS = _appSettings.Myop.BaseUrl+"/op";
            string SCOPE = null;
            string SUB = null;
            string AUD = CLIENT_ID;
            int IAT = 0;
            bool ACTIVE = false;
            var client = await _context.Clients.FindAsync(CLIENT_ID);
            if (client == null) {
                return new Introspect {active = ACTIVE, iss = ISS};
            }
            if (client.AccessType == "confidential") {
                if (client.ClientSecret != CLIENT_SECRET) return new Introspect {active = ACTIVE, iss = ISS};
            } else if (client.AccessType == "public") {
                if (client.GrantTypes != "password" && client.GrantTypes != "authorization_code" && client.GrantTypes != "implicit") return new Introspect {active = ACTIVE, iss = ISS};
                if (CLIENT_SECRET != null) return new Introspect {active = ACTIVE, iss = ISS};
            } else {
                return new Introspect {active = ACTIVE, iss = ISS};
            }
            var token = await _context.Tokens.FirstOrDefaultAsync(e => e.AccessToken == TOKEN);
            if (token != null) {
                if (CLIENT_ID == token.ClientId) {
                    SCOPE = token.Scope;
                    SUB = token.UserId;
                    int unixTimestamp = (int)(DateTime.Now.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                    IAT = (int)(token.Iat.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                    if (unixTimestamp - IAT < _appSettings.Myop.AccessTokenExpiration) ACTIVE = true;
                } else {
                    IAT=0;
                }
            }
            if (IAT==0) {
                return new Introspect {active = ACTIVE, iss = ISS};
            } else {
                return new Introspect {active = ACTIVE, scope = SCOPE, exp = IAT + _appSettings.Myop.AccessTokenExpiration, iat = IAT, sub = SUB, aud = AUD, iss = ISS};
            }
        }
    }
}

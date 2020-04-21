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
    public class Discovery
    {
        public string issuer { get; set; }
        public string[] grant_types_supported { get; set; }
        public string[] response_types_supported { get; set; }
        public string authorization_endpoint { get; set; }
        public string token_endpoint { get; set; }
        public string introspection_endpoint { get; set; }
        public string jwks_uri { get; set; }
    }

    [Route("op/.well-known/openid-configuration")]
    [ApiController]
    public class DiscoveryController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly AppSettings _appSettings;
        public DiscoveryController(ApplicationDbContext context, IOptions<AppSettings> optionsAccessor)
        {
            _context = context;
            _appSettings = optionsAccessor.Value;
        }

        // GET: op/.well-known/openid-configuration
        [HttpGet]
        public async Task<ActionResult<Discovery>> doGet()
        {
            Discovery discovery = new Discovery {issuer = _appSettings.Myop.BaseUrl+"/op", grant_types_supported = new string[] {"authorization_code","implicit","client_credentials","password","refresh_token"}, response_types_supported = new string[] {"code","id_token","token id_token"}, authorization_endpoint = _appSettings.Myop.BaseUrl+"/op/auth", token_endpoint = _appSettings.Myop.BaseUrl+"/op/token", introspection_endpoint = _appSettings.Myop.BaseUrl+"/op/introspect", jwks_uri = _appSettings.Myop.BaseUrl+"/op/keys"};
            await _context.SaveChangesAsync();
            return discovery;
        }
    }
}

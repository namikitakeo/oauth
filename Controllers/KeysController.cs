using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using myop.Models;

namespace myop.Controllers
{
    public class Key
    {
        public string kty { get; set; }
        public string kid { get; set; }
        public string use { get; set; }
        public string alg { get; set; }
        public string n { get; set; }
        public string e { get; set; }
    }
    public class Jks
    {
        public Key[] keys { get; set; }
    }

    [Route("op/keys")]
    [ApiController]
    public class KeysController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        public KeysController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: op/keys
        [HttpGet]
        public async Task<ActionResult<Jks>> doGet()
        {
            // Key key = new Key {kty = "RSA", kid = "testkey", use = "sig", alg = "RS256", n = "AJ56Fm5BN0rQqvRLUGhR6IBjNZWiXRpQ5FVFSgBizmQtD1wNGqjOeK0jKLtE-oTGXSbUTCkTzH1HUQcZwJJ79wGmhC04lPVUnQ0SwQl-K63mm0GgrTgZDHv55MOf_eB832Gu39iJ2QvjjGwNVgAbb3aU4V6f6KFTu6cZtKO9WHCWwbEV4VoSNJOFZyZUl-GoxC86o66PcckePzsjstjHaDtNU7zidJiKT0bZ0WtcQLbzxOY2e1KOLDCUkUmD3c-XSIREWVvpMNszNWQ9w6HkxUkCls71g_aumW7WlDCI8AkAcsJxh7nPZKJFBRMAeA2MqtbebEq3KUZVlax675R3Ouk", e = "AQAB"};
            Key key = new Key {kty = "RSA", kid = "testkey", use = "sig", alg = "RS256", n = "68AgRr2w3WutTMV0k8AK076qtQamauVhRvKcyRrT8GP7FQIJTRLnunmmwR78PC4R868GnfoW54l3FX-DAywtuS1NVrKZpsDDF5bBBD9-k2y8gJfALvVV6RIVsHmWMeulMb6o9OVDC4HktBSJGpaFy2kKNhde5PaWhnoq5lCjnLSCEbfZxTVrTFAaF3Mr4Thww5xm7lnSICYotDycTIe8C5ErsBhJFNX82V40pO8TNU2IDY7Zf_fpsUzI6eOoAxKBY7nUOX8bKf5WMo3-ztYCLoN4Oaf9xmjWT-zjEnsozIctAQ_JjZcofEhqLTKjsVvRIoweUqP9EBfsHn7UkJSTCQ", e = "AQAB"};
            Jks jks = new Jks {keys = new Key[] {key}};
            await _context.SaveChangesAsync();
            return jks;
        }
    }
}
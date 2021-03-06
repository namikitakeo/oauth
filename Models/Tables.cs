using System;
using System.IO;
using System.ComponentModel;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using System.Text;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;

namespace myop.Models
{
  public static class Util
  {
    public static bool ByteArraysEqual(byte[] a, byte[] b)
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

    public static bool PasswordEqual(string PasswordHash, string Password)
    {
      byte[] buffer4;
      byte[] src = Convert.FromBase64String(PasswordHash);
      byte[] dst = new byte[0x10];
      Buffer.BlockCopy(src, 0x0D, dst, 0, 0x10);
      byte[] buffer3 = new byte[0x20];
      Buffer.BlockCopy(src, 0x1D, buffer3, 0, 0x20);
      using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(Password, dst, 0x2710, HashAlgorithmName.SHA256))
      {
        buffer4 = bytes.GetBytes(0x20);
      }
      return ByteArraysEqual(buffer3, buffer4);
    }

    public static string GetAtHash(string random)
    {
      SHA256Managed hashstring = new SHA256Managed();
      byte[] bytes = Encoding.Default.GetBytes(random);
      byte[] hash = hashstring.ComputeHash(bytes);
      Byte[] sixteen_bytes = new Byte[16];
      Array.Copy(hash, sixteen_bytes, 16);
      return Convert.ToBase64String(sixteen_bytes).Trim('=');
    }

    public static string GetIdToken(Claim[] claims, string client_id, string base_url)
    {
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
      issuer: base_url+"/op",
        audience: client_id,
        claims: claims,
        notBefore: DateTime.Now,
        expires: DateTime.Now.AddMinutes(600),
        issuedAt: DateTime.Now
      );
      var jwt = new JwtSecurityToken(jwtHeader, jwtPayload);
      return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
  }

  public class ApplicationDbContext : IdentityDbContext
  {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) {}
//  public class myopContext : DbContext
//  {
        public DbSet<Client> Clients { get; set; }
        public DbSet<Token> Tokens { get; set; }
        public DbSet<Code> Codes { get; set; }
//        protected override void OnConfiguring(DbContextOptionsBuilder options)
//            => options.UseSqlite("Data Source=app.db");
  }

  public class AppSettings
  {
    public Myop Myop { get; set; }
  }

  public class Myop
  {
    public string BaseUrl { get; set; }
    public int AccessTokenExpiration { get; set; }
    public int RefreshTokenExpiration { get; set; }
  }

  public class Client
  {
    [Key]
    [DisplayName("client_id")]
    public string ClientId { get; set; }

    [DisplayName("client_secret")]
    public string ClientSecret { get; set; }

    [DisplayName("access_type")]
    public string AccessType { get; set; }

    [DisplayName("redirect_uris")]
    public string RedirectUris { get; set; }

    [DisplayName("grant_types")]
    public string GrantTypes { get; set; }

    [DisplayName("allowed_scope")]
    public string AllowedScope { get; set; }

    [DisplayName("client_name")]
    public string ClientName { get; set; }

    [DisplayName("auth_method")]
    public string AuthMethod { get; set; }

    [DisplayName("iat")]
    public DateTime Iat { get; set; }
  }

  public class Token
  {
    [Key]
    [DisplayName("user_id")]
    public string UserId { get; set; }

    [DisplayName("access_token")]
    public string AccessToken { get; set; }

    [DisplayName("client_id")]
    public string ClientId { get; set; }

    [DisplayName("refresh_token")]
    public string RefreshToken { get; set; }

    [DisplayName("scope")]
    public string Scope { get; set; }

    [DisplayName("iat")]
    public DateTime Iat { get; set; }
  }

  public class Code
  {
    [Key]
    [DisplayName("code")]
    public string CodeId { get; set; }

    [DisplayName("user_id")]
    public string UserId { get; set; }

    [DisplayName("client_id")]
    public string ClientId { get; set; }

    [DisplayName("nonce")]
    public string Nonce { get; set; }

    [DisplayName("iat")]
    public DateTime Iat { get; set; }
  }
}

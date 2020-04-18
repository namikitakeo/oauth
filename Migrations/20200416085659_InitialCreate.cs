using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace myop.Migrations
{
    public partial class InitialCreate : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Clients",
                columns: table => new
                {
                    ClientId = table.Column<string>(nullable: false),
                    ClientSecret = table.Column<string>(nullable: true),
                    AccessType = table.Column<string>(nullable: true),
                    RedirectUris = table.Column<string>(nullable: true),
                    GrantTypes = table.Column<string>(nullable: true),
                    AllowedScope = table.Column<string>(nullable: true),
                    ClientName = table.Column<string>(nullable: true),
                    AuthMethod = table.Column<string>(nullable: true),
                    Iat = table.Column<DateTime>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Clients", x => x.ClientId);
                });

            migrationBuilder.CreateTable(
                name: "Codes",
                columns: table => new
                {
                    CodeId = table.Column<string>(nullable: false),
                    UserId = table.Column<string>(nullable: true),
                    Nonce = table.Column<string>(nullable: true),
                    Iat = table.Column<DateTime>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Codes", x => x.CodeId);
                });

            migrationBuilder.CreateTable(
                name: "Tokens",
                columns: table => new
                {
                    UserId = table.Column<string>(nullable: false),
                    AccessToken = table.Column<string>(nullable: true),
                    RefreshToken = table.Column<string>(nullable: true),
                    Scope = table.Column<string>(nullable: true),
                    Iat = table.Column<DateTime>(nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tokens", x => x.UserId);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Clients");

            migrationBuilder.DropTable(
                name: "Codes");

            migrationBuilder.DropTable(
                name: "Tokens");
        }
    }
}

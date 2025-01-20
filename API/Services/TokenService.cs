using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace API.Services;

public class TokenService(IConfiguration config) : ITokenService
{
    public string CreateToken(AppUser user)
    {
        // if the token key is null
        var tokenKey = config["TokenKey"] ?? throw new Exception("Cannot access tokenkey from appsettings");
        if(tokenKey.Length < 64 ) throw new Exception("Token key needs to be longer");
        // Create a symmetric key, meaning one key for decryption and encryption
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));

        // what does the user claim about himself
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.UserName)
        };

        // Represents the cryptographic key and security algorithms that are used to generate a digital signature.
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        // Self explanatory
        var tokenDescriptor = new SecurityTokenDescriptor 
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = creds
        };
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);

    }
}

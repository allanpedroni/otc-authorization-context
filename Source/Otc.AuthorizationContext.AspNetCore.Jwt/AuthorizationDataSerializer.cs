using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Otc.AuthorizationContext.Abstractions;

namespace Otc.AuthorizationContext.AspNetCore.Jwt
{
    public class AuthorizationDataSerializer<TAuthorizationData> : IAuthorizationDataSerializer<TAuthorizationData>
        where TAuthorizationData : IAuthorizationData
    {
        private readonly JwtConfiguration jwtConfiguration;
        private readonly JwtSecurityTokenHandler tokenHandler;

        public AuthorizationDataSerializer(JwtConfiguration jwtConfiguration)

        {
            this.jwtConfiguration = jwtConfiguration ??
                throw new ArgumentNullException(nameof(jwtConfiguration));
            tokenHandler = new JwtSecurityTokenHandler();
        }

        public string Serialize(TAuthorizationData authorizationData)
        {
            return tokenHandler.WriteToken(GetJwtSecurityToken(authorizationData));

            JwtSecurityToken GetJwtSecurityToken(TAuthorizationData authorizationData)
            {
                var claims = new Claim[]
                {
                new Claim(JwtRegisteredClaimNames.UniqueName, authorizationData.UserId),
                new Claim(JwtConfiguration.AuthorizationDataJwtTypeName, JsonSerializer.Serialize(authorizationData))
                };

                return new(
                    issuer: jwtConfiguration.Issuer,
                    audience: jwtConfiguration.Audience,
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(jwtConfiguration.ExpiresMinutes),
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfiguration.SecretKey)),
                        SecurityAlgorithms.HmacSha256)
                );
            }
        }
    }
}

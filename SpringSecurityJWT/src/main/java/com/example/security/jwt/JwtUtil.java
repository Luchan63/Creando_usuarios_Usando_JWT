package com.example.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
@Slf4j
public class JwtUtil
{
    @Value("${jwt.secret.key}")
    private String secretKey; // nos ayuda a firmar nuestro metodo

    @Value("${jwt.time.expiration}")
    private  String timeExpiratiKey;

    //crear un token de acceso
    public String generalToken(String usrname)
    {
        return Jwts.builder()
                .setSubject(usrname)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + Long.parseLong(timeExpiratiKey)))
                .signWith(getSignaturKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    //validar el token de acceso
    public boolean isTokenValid(String token)
    {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSignaturKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return true;
        }catch (Exception e)
        {
            log.error("token invalido, error: ".concat(e.getMessage()));
            return false;
        }
    }

    // objetener el username de token
    public String getUsernameFromToken(String token)
    {
        return getClaims(token,Claims::getSubject);
    }
    // obtener un solo claim
    public <T> T getClaims(String token, Function<Claims,T> claimsTFunction)
    {
        Claims claims = extractAllClaims(token);
        return claimsTFunction.apply(claims);
    }

    // obtener todo lo cleains del tokens
    public Claims extractAllClaims(String token)
    {
        return Jwts.parserBuilder()
                .setSigningKey(getSignaturKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // obtener firma del token
    public Key getSignaturKey()
    {
        byte[] keyBayte = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBayte); // obtenermos la firma de nuestro token
    }

}

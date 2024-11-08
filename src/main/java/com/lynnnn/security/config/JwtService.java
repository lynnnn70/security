package com.lynnnn.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;


@Service
public class JwtService {

    final static Logger log = LoggerFactory.getLogger(JwtService.class);

    private static final String SECRET_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTczMDAzNjM0MCwiaWF0IjoxNzMwMDM2MzQwfQ.UDhYD9DZz-SUk3_025lph7LqVxvK5ixM2Es-upVywuc";

    //從 JWT 中提取用戶名
    //Claims::getSubject 是指向 JWT 的 Payload 部分中的 sub 聲明（主題）。通常是用戶名或用戶 ID，但具體取決於你在生成 JWT 時如何設置
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //從 JWT 中提取特定的 Claims(ex用戶名、過期時間)
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllCLaims(token);
        return claimsResolver.apply(claims);
    }

    //生成不包含額外 Claim 的 JWT
    public String generateToken(UserDetails userDetails) {
        return  generateToken(new HashMap<>(), userDetails);
    }

    //生成包含特定 Claim 的JWT(ex用戶名、發行時間、過期時間(設24小時))，並使用 HMAC-SHA256 進行簽名生成 token
    public String generateToken(Map<String, Objects> extractClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extractClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 *24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // to validate if the token belongs to this user details
    // UserDetails 來自Spring security 的UserDetails接口 代表當前經過身份驗證的使用者信息對象
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpirations(token).before(new Date());
    }

    //從 JWT 中提取過期時間
    private Date extractExpirations(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //從 token 中提取所有 Claim
    private Claims extractAllCLaims(String token){
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        }catch (JwtException | IllegalArgumentException e) {
            log.error("Failed to parse token ", e);
            throw new InvalidTokenException("Token is invalid or expired");
        }
    }

    //生成 JWT 解析用的簽名密鑰
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);
    }
}

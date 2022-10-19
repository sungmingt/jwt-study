package codestates.jwt.study.domain.util;

import codestates.jwt.study.domain.redis.RedisUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final RedisUtil redisUtil;

    @Value("${spring.jwt.secret}")
    public String SECRET_KEY;

    public static final String PREFIX = "Bearer ";
    public static final String AUTHORIZATION = "Authorization";

    public static final long ACCESS_TOKEN_VALIDATION_SECOND = 1000L * 10;
    public static final long REFRESH_TOKEN_VALIDATION_SECOND = 1000L * 60 * 24 * 2;

    public static final String ACCESS_TOKEN_NAME = "accessToken";
    public static final String REFRESH_TOKEN_NAME = "refreshToken";

    public String createAccessToken(String email) {
        return JWT.create()
                .withSubject(SECRET_KEY)
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDATION_SECOND))
                .withClaim("email", email)
                .sign(Algorithm.HMAC512(SECRET_KEY));
    }

    public String createRefreshToken(String email) {
        return JWT.create()
                .withSubject(SECRET_KEY)
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDATION_SECOND))
                .withClaim("email", email)
                .sign(Algorithm.HMAC512(SECRET_KEY));
    }

    public String verifyToken(String token) {
        //토큰 만료 시 refresh token 만료여부 조회
        if (isExpired(token)) {
            String email = getEmail(token);
            String refreshToken = redisUtil.getData(email);

            //refresh token 도 만료 시 강제 로그아웃
            if (refreshToken == null) {
                throw new RuntimeException("refresh token 만료, 강제 로그아웃");
            }

            //access token 새로 발급
            String accessToken = createAccessToken(email);
            //refresh token 만료시간 연장 (redis key값 덮어씌우기 되는지)
            redisUtil.setDataExpire(email, refreshToken, REFRESH_TOKEN_VALIDATION_SECOND);

            return accessToken;
        }

        return JWT.require(Algorithm.HMAC512(SECRET_KEY))
                .build()
                .verify(token)
                .getClaim("email")
                .asString();
    }

    private boolean isExpired(String token) {
        return JWT.decode(token).getExpiresAt().before(new Date());
    }

    private String getEmail(String token) {
        return JWT.decode(token).getClaim(token).asString();
    }

//    public Map<String,Object> getClaimsFromToken(String token, String keys){
//        DecodedJWT decodedJWT = JWT.decode(token);
//        String key = keys.equals("refresh") ? REFRESH_TOKEN_NAME : ACCESS_TOKEN_NAME;
//        String email = decodedJWT.getClaim("email").asString();
//        Long id = decodedJWT.getClaim("id").asLong();
//        return Map.of("email",email,"id",id);
//    }
}


package codestates.jwt.study.domain.util;

import codestates.jwt.study.domain.redis.RedisUtil;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtUtil {

    private final RedisUtil redisUtil;

    @Value("${spring.jwt.secret}")
    public String SECRET_KEY;

    public static final String PREFIX = "Bearer ";
    public static final String AUTHORIZATION = "Authorization";
    public static final String EMAIL = "email";

    public static final long ACCESS_TOKEN_VALIDATION_SECOND = 1000L * 60 * 30;  //30분
    public static final long REFRESH_TOKEN_VALIDATION_SECOND = 1000L * 60 * 60 * 24 * 3;  //3일

    public static final String ACCESS_TOKEN_NAME = "accessToken";
    public static final String REFRESH_TOKEN_NAME = "refreshToken";

    public String createAccessToken(String email) {
        return PREFIX + JWT.create()
                .withSubject(SECRET_KEY)
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDATION_SECOND))
                .withClaim(EMAIL, email)
                .sign(Algorithm.HMAC512(SECRET_KEY));
    }

    public String createRefreshToken(String email) {
        return JWT.create()
                .withSubject(SECRET_KEY)
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDATION_SECOND))  ///////////////////////
                .withClaim(EMAIL, email)
                .sign(Algorithm.HMAC512(SECRET_KEY));
    }

    public Map<String, String> verifyToken(String token) {

        //토큰 만료 시 refresh token 만료여부 조회
        if (isExpired(token)) {
            log.info("### access token expired- {}", token);

            String email = getEmail(token);

            log.info("### email - {}", email);

            String refreshToken = redisUtil.getData(email);

            log.info("### refreshToken - {}", refreshToken);

            //refresh token 도 만료 시 강제 로그아웃
            if (refreshToken == null) {
                log.info("### refresh token expired - {}", email);

                throw new RuntimeException("refresh token 만료, 강제 로그아웃");
            }

            //access token 새로 발급
            String accessToken = createAccessToken(email);
            //기존 refresh token 만료시간 초기화
            redisUtil.setDataExpire(email, refreshToken, REFRESH_TOKEN_VALIDATION_SECOND);

            return Map.of(ACCESS_TOKEN_NAME, accessToken);
        }

        return Map.of(EMAIL,
                JWT.require(Algorithm.HMAC512(SECRET_KEY))
                        .build()
                        .verify(token)
                        .getClaim(EMAIL)
                        .asString());
    }

    private boolean isExpired(String token) {
        return JWT.decode(token).getExpiresAt().before(new Date());
    }

    public Long getExpiration(String token) {
        return JWT.decode(token).getExpiresAt().getTime() - System.currentTimeMillis();
    }

    private String getEmail(String token) {
        return JWT.decode(token).getClaim(EMAIL).asString();
    }

//    public Map<String,Object> getClaimsFromToken(String token, String keys){
//        DecodedJWT decodedJWT = JWT.decode(token);
//        String key = keys.equals("refresh") ? REFRESH_TOKEN_NAME : ACCESS_TOKEN_NAME;
//        String email = decodedJWT.getClaim(EMAIL).asString();
//        Long id = decodedJWT.getClaim("id").asLong();
//        return Map.of("email",email,"id",id);
//    }
}


package codestates.jwt.study.domain.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;

import java.util.Date;

public class JwtUtil {

    @Value("${spring.jwt.secret}")
    public static String SECRET_KEY;

    public static final String PREFIX = "Bearer ";
    public static final String AUTHORIZATION = "Authorization";

    public static final long ACCESS_TOKEN_VALIDATION_SECOND = 1000L * 10;
    public static final long REFRESH_TOKEN_VALIDATION_SECOND = 1000L * 60 * 24 * 2;

    public static final String ACCESS_TOKEN_NAME = "accessToken";
    public static final String REFRESH_TOKEN_NAME = "refreshToken";

    public static String createAccessToken(String email) {
        return JWT.create()
                .withSubject(SECRET_KEY)
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALIDATION_SECOND))
                .withClaim("email", email)
                .sign(Algorithm.HMAC512(SECRET_KEY));
    }

    public static String createRefreshToken(String email) {
        return JWT.create()
                .withSubject(SECRET_KEY)
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALIDATION_SECOND))
                .withClaim("email", email)
                .sign(Algorithm.HMAC512(SECRET_KEY));
    }
}

package codestates.jwt.study.web;

import codestates.jwt.study.domain.AuthService;
import codestates.jwt.study.domain.Member;
import codestates.jwt.study.domain.redis.RedisUtil;
import codestates.jwt.study.domain.util.JwtUtil;
import codestates.jwt.study.web.dto.LoginRequest;
import codestates.jwt.study.web.dto.Response;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static codestates.jwt.study.domain.util.JwtUtil.*;
import static codestates.jwt.study.domain.util.JwtUtil.ACCESS_TOKEN_NAME;
import static codestates.jwt.study.domain.util.JwtUtil.REFRESH_TOKEN_NAME;

@RestController
@RequestMapping("/member")
@RequiredArgsConstructor
public class MemberController {

    private final AuthService authService;
    private final RedisUtil redisUtil;

    /**
     * 가입
     */
    @PostMapping("/signup")
    public Response signUpUser(@RequestBody Member member) {

        authService.signUpUser(member);
        return new Response("success", "회원가입 성공");
    }

    /**
     * 로그인
     */
//    @PostMapping("/login")
    public Response login(@RequestBody LoginRequest loginRequest,
                          HttpServletRequest req,
                          HttpServletResponse res) {
            final Member member = authService.loginUser(loginRequest.getEmail(), loginRequest.getPassword());

            final String accessToken = createAccessToken(member.getEmail());
            final String refreshToken = createRefreshToken(member.getEmail());

            redisUtil.setDataExpire(refreshToken, member.getEmail(), REFRESH_TOKEN_VALIDATION_SECOND);
            res.addHeader(ACCESS_TOKEN_NAME, accessToken);
            res.addHeader(REFRESH_TOKEN_NAME, refreshToken);
            return new Response("success", "로그인에 성공했습니다.");
    }
}

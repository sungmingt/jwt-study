package codestates.jwt.study.web.controller;

import codestates.jwt.study.domain.AuthService;
import codestates.jwt.study.domain.Member;
import codestates.jwt.study.domain.redis.RedisUtil;
import codestates.jwt.study.domain.util.JwtUtil;
import codestates.jwt.study.web.dto.LoginRequest;
import codestates.jwt.study.web.dto.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static codestates.jwt.study.domain.util.JwtUtil.*;
import static codestates.jwt.study.domain.util.JwtUtil.ACCESS_TOKEN_NAME;
import static codestates.jwt.study.domain.util.JwtUtil.REFRESH_TOKEN_NAME;

@RestController
@RequiredArgsConstructor
@Slf4j
public class MemberController {

    private final AuthService authService;
    private final RedisUtil redisUtil;
    private final JwtUtil jwtUtil;

    /**
     * 가입
     */
    @PostMapping("/signup")
    public Response signUpUser(@RequestBody Member member) {

        System.out.println("=======================" + jwtUtil.SECRET_KEY);
        authService.signUpUser(member);
        return new Response("success", "회원가입 성공");
    }

    /**
     * 로그인
     */
    @PostMapping("/login")
    public Response login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
            final Member member = authService.loginUser(loginRequest.getEmail(), loginRequest.getPassword());

            final String accessToken = jwtUtil.createAccessToken(member.getEmail());
            final String refreshToken = jwtUtil.createRefreshToken(member.getEmail());

            redisUtil.setDataExpire(member.getEmail(), refreshToken, REFRESH_TOKEN_VALIDATION_SECOND);
            response.addHeader(ACCESS_TOKEN_NAME, accessToken);
            response.addHeader(REFRESH_TOKEN_NAME, refreshToken);  //실제로는 refresh token을 반환하지 않는 방법을 쓰는게 좋다.
            return new Response("success", "로그인에 성공했습니다.");
    }

    /**
     * 로그아웃
     */
    @PostMapping("/custom/logout")
    public Response logout(HttpServletRequest request) {

        //refresh token DB에서 삭제
        String email = (String) request.getAttribute("email");
        log.info("### controller - email = {}", email);
        redisUtil.deleteData(email);

        //access token blacklist에 등록
        String accessToken = request.getHeader(ACCESS_TOKEN_NAME).replace(PREFIX, "");
        Long expiration = jwtUtil.getExpiration(accessToken);
        log.info("### access token 남은 시간 - {}", expiration);

        redisUtil.setBlackList(accessToken, expiration);

        return new Response("success", "로그아웃에 성공했습니다.");
    }
}

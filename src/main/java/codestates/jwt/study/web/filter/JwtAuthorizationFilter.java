package codestates.jwt.study.web.filter;

import codestates.jwt.study.domain.Member;
import codestates.jwt.study.domain.oauth.PrincipalDetails;
import codestates.jwt.study.domain.MemberRepository;
import codestates.jwt.study.domain.redis.RedisUtil;
import codestates.jwt.study.domain.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

import static codestates.jwt.study.domain.util.JwtUtil.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final MemberRepository memberRepository;
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("인증/권한이 필요한 url 요청 - {}", request.getRequestURI());

        String jwtHeader = request.getHeader(ACCESS_TOKEN_NAME);

        log.info("### 헤더 확인");
        if (jwtHeader == null || !jwtHeader.startsWith(PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String token = jwtHeader.replace(PREFIX, "");
        log.info("### 토큰 확인 - {}", token);

        if (redisUtil.isBlacklist(token)) {
            log.info("### access token from blacklist - {}", token);
            throw new RuntimeException("사용할 수 없는 토큰입니다.");
        }


        Map<String, String> verified = jwtUtil.verifyToken(token);

        log.info("### 토큰 유효 확인");

        if (verified.containsKey(ACCESS_TOKEN_NAME)) {
            response.addHeader(ACCESS_TOKEN_NAME, verified.get(ACCESS_TOKEN_NAME));
            chain.doFilter(request, response);
            return;
            // 여기서 요청이 끝나기 때문에 클라이언트에서 새로 발급받은 access token을 받아 다시 요청을 보내야한다.
        }

        String email = verified.get("email");

        if (email != null) {
            log.info("### 이메일 확인 - {}", email);
            Member memberEntity = memberRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("존재하지 않는 이메일입니다."));

            log.info("### 이메일 유효 확인");
            PrincipalDetails principalDetails = new PrincipalDetails(memberEntity);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.info("### set context holder");

            if (request.getRequestURI().equals("/custom/logout")) {
                log.info("### filter - email ={}", email);
                request.setAttribute("email", email);
            }

            chain.doFilter(request, response);
        }
        log.info("### 첫 do filter");
        chain.doFilter(request, response);
    }
}
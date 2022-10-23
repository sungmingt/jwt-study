package codestates.jwt.study.web.filter;

import codestates.jwt.study.domain.Member;
import codestates.jwt.study.domain.MemberRepository;
import codestates.jwt.study.domain.oauth.PrincipalDetails;
import codestates.jwt.study.domain.redis.RedisUtil;
import codestates.jwt.study.domain.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.security.sasl.AuthenticationException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

import static codestates.jwt.study.domain.util.JwtUtil.ACCESS_TOKEN_NAME;
import static codestates.jwt.study.domain.util.JwtUtil.PREFIX;

//Security filter → 권한 및 인증이 필요한 주소를 요청 시 BasicAuthenticationFilter를 반드시 진행하게 되어있습니다.
//권한이나 인증이 필요하지 않을 경우 BasicAuthenticationFilter는 적용되지 않습니다.

//인증 권한이 필요한 url에 접속할 때 이 필터가 적용되도록 할 것이다.
@Slf4j
public class JwtAuthorizationFilter2 extends BasicAuthenticationFilter {

    private final MemberRepository memberRepository;
    private final JwtUtil jwtUtil;

    public JwtAuthorizationFilter2(AuthenticationManager authenticationManager, MemberRepository memberRepository, JwtUtil jwtUtil) {
        super(authenticationManager);
        this.memberRepository = memberRepository;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("인증/권한이 필요한 url 요청 - {}", request.getRequestURI());

        String jwtHeader = request.getHeader(ACCESS_TOKEN_NAME);

        if (jwtHeader == null || !jwtHeader.startsWith(PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String token = jwtHeader.replace(PREFIX, "");
        Map<String, String> verified = jwtUtil.verifyToken(token);

        if (verified.containsKey(ACCESS_TOKEN_NAME)) {
            response.addHeader(ACCESS_TOKEN_NAME, verified.get(ACCESS_TOKEN_NAME));
            chain.doFilter(request, response);
            return;
        }

        String email = verified.get("email");

        if (email != null) {
            Member memberEntity = memberRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("존재하지 않는 이메일입니다."));

            PrincipalDetails principalDetails = new PrincipalDetails(memberEntity);
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            //로그아웃 시 email 전달 (LogoutHandler를 상속해 filter chain 에 등록해서 구현하면 더 편리함)
            if (request.getRequestURI().equals("/logout")) {
                request.setAttribute("email", email);
            }

            chain.doFilter(request, response);
        }

        super.doFilterInternal(request, response, chain);
    }
}

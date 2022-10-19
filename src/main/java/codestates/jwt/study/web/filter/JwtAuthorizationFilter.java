package codestates.jwt.study.web.filter;

import codestates.jwt.study.domain.Member;
import codestates.jwt.study.domain.oauth.PrincipalDetails;
import codestates.jwt.study.domain.MemberRepository;
import codestates.jwt.study.domain.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static codestates.jwt.study.domain.util.JwtUtil.*;
//Security filter → 권한 및 인증이 필요한 주소를 요청 시 BasicAuthenticationFilter를 반드시 진행하게 되어있습니다.
//권한이나 인증이 필요하지 않을 경우 BasicAuthenticationFilter는 적용되지 않습니다.

//인증 권한이 필요한 url에 접속할 때 이 필터가 적용되도록 할 것이다.
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final MemberRepository memberRepository;
    private final JwtUtil jwtUtil;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository, JwtUtil jwtUtil) {
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
        String email = jwtUtil.verifyToken(token);

        if (email != null) {
            Member memberEntity = memberRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("존재하지 않는 이메일입니다."));

            PrincipalDetails principalDetails = new PrincipalDetails(memberEntity);
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
        super.doFilterInternal(request, response, chain);
    }
}

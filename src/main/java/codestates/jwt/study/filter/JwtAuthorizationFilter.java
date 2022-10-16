package codestates.jwt.study.filter;

import codestates.jwt.study.model.Member;
import codestates.jwt.study.oauth.PrincipalDetails;
import codestates.jwt.study.repostitory.MemberRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
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
//Security filter → 권한 및 인증이 필요한 주소를 요청 시 BasicAuthenticationFilter를 반드시 진행하게 되어있습니다.
//권한이나 인증이 필요하지 않을 경우 BasicAuthenticationFilter는 적용되지 않습니다.

//인증 권한이 필요한 url에 접속할 때 이 필터가 적용되도록 할 것이다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final MemberRepository memberRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, MemberRepository memberRepository) {
        super(authenticationManager);
        this.memberRepository = memberRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증/권한이 필요한 url 요청됨");

        String jwtHeader = request.getHeader("Authorization");

        if (jwtHeader == null || !jwtHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String token = jwtHeader.replace("Bearer ", "");
//        DecodedJWT decodedJWT = JWT.decode(token);
        String email = JWT.require(Algorithm.HMAC512("cos_jwt_token"))
                .build()
                .verify(token)
                .getClaim("email")
                .asString();

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

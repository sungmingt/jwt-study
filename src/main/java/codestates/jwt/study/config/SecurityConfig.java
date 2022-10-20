package codestates.jwt.study.config;

import codestates.jwt.study.domain.MemberRepository;
import codestates.jwt.study.web.filter.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity(debug = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;
    private final MemberRepository memberRepository;
    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.headers().frameOptions().disable();
        //session / cookie를 만들지 않음
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .formLogin().disable()
                .httpBasic().disable() //기본 인증 로그인 방식이다.
                .apply(new CustomDsl())/////////////
                .and()
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/api/v1/manager/**").access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**").access("hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/user/**").authenticated()
                .anyRequest().permitAll();

//                .addFilter(corsFilter) // 추가
//                .addFilterBefore(new FirstFilter(), BasicAuthenticationFilter.class);  //추가

        return http.build();
    }

    //이전에는 .addFilter(new JwtAuthenticationFilter(authenticationManager())) 메서드를 통해 쉽게 처리할 수 있었습니다.
    //하지만 WebSecurityConfigureAdapter가 deprecated되면서 내부에 클래스를 만들어주거나 별도의 처리가 필요해졌습니다.
    //CustomDsl이라는 내부 클래스를 만들어 .addFilter(new JwtAuthenticationFilter(authenticationManager())) 처리를 통해 해당 필터를 적용시킵니다.

    public class CustomDsl extends AbstractHttpConfigurer<CustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
            builder
                    .addFilter(corsFilter)
//                    .addFilter(new JwtAuthenticationFilter2(authenticationManager))
//                    .addFilter(new JwtAuthorizationFilter2(authenticationManager, memberRepository, new JwtUtil(new RedisUtil())));
                    .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class);
            //만일 이렇게 필터들을 추가하면, 기존의 필터체인들도 똑같이 수행되나??
        }
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

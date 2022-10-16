package codestates.jwt.study.controller;

import codestates.jwt.study.model.Member;
import codestates.jwt.study.repostitory.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }

    //토큰 전송(FirstFilter)
    @PostMapping("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    //회원가입
    @PostMapping("/join")
    public String join(@RequestBody Member member) {
        member.setPassword(bCryptPasswordEncoder.encode(member.getPassword()));
        member.setRoles("ROLE_USER");
        memberRepository.save(member);
        return "회원 가입 완료";
    }



    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}

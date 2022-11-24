package codestates.jwt.study.domain;

import codestates.jwt.study.web.dto.SignupRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;

    public void signUp(SignupRequest request) {
        Member member = new Member(request.getUsername(), request.getEmail(), request.getPassword());
        member.setRole("USER");

        memberRepository.save(member);
    }

    public String loginUser(String email, String password) {
        Member member = memberRepository.findByEmail(email).
                orElseThrow(() -> new RuntimeException("멤버 없음"));

        if (!member.getPassword().equals(password))
            throw new RuntimeException("비밀번호 불일치");

        return email;
    }
}
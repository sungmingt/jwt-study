package codestates.jwt.study.domain;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;

    public void signUpUser(Member member) {
        memberRepository.save(member);
    }

    public Member loginUser(String email, String password) {
        Member member = memberRepository.findByEmail(email).
                orElseThrow(() -> new RuntimeException("멤버 없음"));

        if (!member.getPassword().equals(password))
            throw new RuntimeException("비밀번호 불일치");

        return member;
    }
}
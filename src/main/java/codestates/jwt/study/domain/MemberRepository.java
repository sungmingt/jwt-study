package codestates.jwt.study.domain;

import codestates.jwt.study.domain.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByUsername(String member);
    Optional<Member> findByEmail(String email);
}
package codestates.jwt.study.repostitory;

import codestates.jwt.study.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByUsername(String member);
    Optional<Member> findByEmail(String email);
}
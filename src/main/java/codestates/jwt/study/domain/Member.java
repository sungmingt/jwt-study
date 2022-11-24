package codestates.jwt.study.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.util.List;

@Entity
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;
    private String username;
    private String email;
    private String password;
    private List<String> roles;

    public Member(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

//    public List<String> getRoleList() {  //Role 모델을 추가하여 getRoleList를 대체할 수 있음
//        if (this.roles.size() > 0) {
//            return Arrays.asList(this.roles.split(","));
//        }
//        return new ArrayList<>();
//    }

    public void setRole(String role) {
        this.roles.add(role);
    }
}
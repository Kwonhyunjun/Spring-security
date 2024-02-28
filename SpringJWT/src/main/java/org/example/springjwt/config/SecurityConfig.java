package org.example.springjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 회원가입, 로그인, 검증 등의 로직에서 비밀번호를 해시를 이용한 암호화
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {

        return new BCryptPasswordEncoder();
    }

    // 세션 설정
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        /*
         * csrf disable
         * 세션 방식에서는 세선이 항상 고정되기 때문에 csrf 를 필수적으로 방어를 해줘야 함.
         * 하지만 JWT 방식은 세션을 stateless 로 관리하기 때문에 공격 걱정할 필요 없음
         */
        http
                .csrf((auth) -> auth.disable());

        /*
         * Form 로그인 & http basic 인증  두개의 방식 disable
         * JWT로 로그인 할 경우 Form 로그인 방식 & http basic 인증 방식을 disable
         */
        http
                .formLogin((auth) -> auth.disable());

        http
                .httpBasic((auth) -> auth.disable());

        /*
         * API 경로별 인가 작업
         */
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        /*
         * STATELESS로 세션 설정  **중요**
         */
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 받은 파라미터를 빌더한 형태로 리턴
        return http.build();
    }
}

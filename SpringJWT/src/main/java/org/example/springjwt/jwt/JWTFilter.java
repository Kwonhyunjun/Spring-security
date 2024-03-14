package org.example.springjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.springjwt.dto.CustomUserDetails;
import org.example.springjwt.entity.UserEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//@RequiredArgsConstructor
//public class JWTFilter extends OncePerRequestFilter {
//
//    // 검증 메서드 불러오기
//    private final JWTUtil jwtUtil;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        // JWT를 request에서 뽑아내서 검증을 진행
//
//        // request에서 Authorization 헤더를 찾음
//        String authorization = request.getHeader("Authorization");
//
//        //Authorization 헤더 검증
//        if (authorization == null || !authorization.startsWith("Bearer ")) {
//
//            System.out.println("token null");
//            filterChain.doFilter(request, response); // 다음 필터로 보냄
//
//            //조건이 해당되면 메소드 종료 (필수)
//            return;
//        }
//
//        System.out.println("authorization now");
//        //Bearer 부분 제거 후 순수 토큰만 획득
//        String token = authorization.split(" ")[1];
//
//        //토큰 소멸 시간 검증
//        if (jwtUtil.isExpired(token)) {
//
//            System.out.println("token expired");
//            filterChain.doFilter(request, response);
//
//            //조건이 해당되면 메소드 종료 (필수)
//            return;
//        }
//
//        //토큰에서 username과 role 획득
//        String username = jwtUtil.getUsername(token);
//        String role = jwtUtil.getRole(token);
//
//        //userEntity를 생성하여 값 set
//        UserEntity userEntity = new UserEntity();
//        userEntity.setUsername(username);
//        userEntity.setPassword("temppassword"); // 굳이 비밀번호를 가지고 있을 필요가 없기 때문에 더미 데이터 넣음
//        userEntity.setRole(role);
//        System.out.println(role);
//
//        //UserDetails에 회원 정보 객체 담기
//        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);
//
//        //스프링 시큐리티 인증 토큰 생성
//        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
//
//        //세션에 사용자 등록
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//
//        filterChain.doFilter(request, response);
//
//    }
//}

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {

        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //request에서 Authorization 헤더를 찾음
        String authorization= request.getHeader("Authorization");

        //Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {

            System.out.println("token null");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        System.out.println("authorization now");
        //Bearer 부분 제거 후 순수 토큰만 획득
        String token = authorization.split(" ")[1];

        //토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {

            System.out.println("token expired");
            filterChain.doFilter(request, response);

            //조건이 해당되면 메소드 종료 (필수)
            return;
        }

        //토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        //userEntity를 생성하여 값 set
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temppassword");
        userEntity.setRole(role);

        //UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        //스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}

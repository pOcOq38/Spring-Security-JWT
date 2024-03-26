package com.example.springjwt.jwt;

import com.example.springjwt.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Collection;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil){
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {


        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("USERNAME : " + username);

        //authenticationFilter가 dto사용해서(UsernamePasswordAuthenticationToken으로) authentictionManager한테 던져줘서 인증을 받아야 함
        //authentictionManager가 검증을 담당

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null); //3번째 인자는 role 같은게 들어감

        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication){

        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal(); //특정한 유저를 확인
        String username = customUserDetails.getUsername(); //CustomUserDetails에서 유저네임 가져옴


        //role 값 뽑아내기
        String role = "";
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities(); //collection에서 authority를 뽑아낸 다름
        if (!authorities.isEmpty()) {
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();               //iterator로 반복해서 role값 가져옴
        GrantedAuthority auth = iterator.next();

         role = auth.getAuthority();
        }
        String token = jwtUtil.createJwt(username,role, 60*60*10L);  //60*60*10: jwt가 살아 있을 시간

        response.addHeader("Authorization", "Bearer " + token); //"Bearer " 무조건 붙여야 함

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed){

        response.setStatus(401);
    }


}

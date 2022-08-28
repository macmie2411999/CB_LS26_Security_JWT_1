package com.example.demologinjwt.helper;

import com.example.demologinjwt.security.UserService;
import com.google.gson.Gson;
import org.apache.tomcat.util.http.parser.Authorization;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    JwtProvider jwtProvider;

    @Autowired
    UserService userService;

    @Autowired
    AuthenticationManager authenticationManager;

    private Gson gson = new Gson();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String token = getJwtToken(request);
        if(jwtProvider.validationToken(token)){
            // Token hợp lệ
            String jsonData = jwtProvider.decodeToken(token);
            User user = gson.fromJson(jsonData, User.class);
            User userDetail = (User) userService.loadUserByUsername("admin");

            // Gọi lại hàm đăng nhập mặc định của Spring Security
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            System.out.println("Kiem tra data token: " + jsonData);


        } else {
            // Token không phải do hệ thống sinh ra
            System.out.println("Auth: Đăng nhập thất bại");
        }

        // Cho phép đi tiếp vào đường dẫn đang gọi
        filterChain.doFilter(request, response);
    }

    private String getJwtToken(HttpServletRequest request){
        String authenToken = request.getHeader("Authorization");
        if(StringUtils.hasText(authenToken) && authenToken.contains("Bearer")){
            // Loại bỏ chữ Bearer và lấy phần token
            String token = authenToken.substring(7);
            return token;
        }
        return null;
    }
}

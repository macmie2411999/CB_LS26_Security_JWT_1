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

    // Lấy jwtProvider để sử dụng các phương thức xử lý với Token
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

        // gọi hàm getJwtToken, nhận vào request và trả ra Token của request nếu có
        String token = getJwtToken(request);

        // Kiểm tra tính hợp lệ của Token
        if(jwtProvider.validationToken(token)){
            // Token hợp lệ thì tiến hàng giải mã
            String jsonData = jwtProvider.decodeToken(token);
            System.out.println("Data Decode Token: " + jsonData);

            // Biến JSon thành User (Thư viện GSon)
            // User user = gson.fromJson(jsonData, User.class);
            User userDetail = (User) userService.loadUserByUsername("admin");

            // Gọi lại hàm đăng nhập mặc định của Spring Security
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(userDetail, null, userDetail.getAuthorities());
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        } else {
            // Token không phải do hệ thống sinh ra
            System.out.println("Auth: Đăng nhập thất bại");
        }

        // Cho phép đi tiếp vào đường dẫn đang gọi
        filterChain.doFilter(request, response);
    }

    // Hàm lấy Token từ Header nằm trong Request mà user truyền lên
    private String getJwtToken(HttpServletRequest request){
        // Tên Header chứa Token là Authorization (Lưu theo định dạng: "Authorization: Bearer <Token>")
        String authenToken = request.getHeader("Authorization");

        // Kiểm tra null và chứa value theo định dạng "Bearer <Token>"
        if(StringUtils.hasText(authenToken) && authenToken.contains("Bearer")){
            // Loại bỏ chữ Bearer và lấy phần token
            String token = authenToken.substring(7);
            return token;
        }

        // Không có Token thì trả null
        return null;
    }
}

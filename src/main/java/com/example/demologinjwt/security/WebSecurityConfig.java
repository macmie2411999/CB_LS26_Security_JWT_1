package com.example.demologinjwt.security;

import com.example.demologinjwt.helper.JwtAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/* @Configuration: Khi chạy Project thì quyét tìm file config và khởi tạo vào BEAN
 * @EnableWebSecurity: Cho phép custom SS
 * */
@Configuration
@EnableWebSecurity

//  WebSecurityConfigurerAdapter to re-custom all methods related to Authentication
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    // Gọi từ BEAN userService
    @Autowired
    UserService userService;

    // Khai báo chuẩn mã hóa PasswordEncoder (cha của Bscrypt), gửi lên BEAN
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // Khai báo và đưa lên BEAN AuthenticationManager để sử dụng trong Controller (khi gọi link login)
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public JwtAuthFilter jwtAuthFilter(){
        return new JwtAuthFilter();
    }

    // Sử dụng customUserDetailService tự định nghĩa thay cho config mặc định của SS
    //.passwordEncoder(<Type>): Khai báo chuẩn mã hóa
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // Chống dùng session tấn công
                .csrf().disable()
                // cors: Không cho phép truy cập vào tài nguyên nếu không đúng domain, mặc định enable
                // Vì enable nên nếu không quy định domain nào được phép gọi nó thì sẽ lỗi 403
                .cors().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeHttpRequests()
                // Khi vào link login thì cho qua không cần Authen
                .antMatchers("/api/v1/login").permitAll()
                .anyRequest().authenticated()
                .and().addFilterBefore(jwtAuthFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}

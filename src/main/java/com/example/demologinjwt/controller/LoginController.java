package com.example.demologinjwt.controller;

import com.example.demologinjwt.helper.JwtProvider;
import com.example.demologinjwt.payload.LoginRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
public class LoginController {

    // Để thực hiện chức năng Login thì cần AuthenticationManager vì login thành công thì mới trả Token
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtProvider jwtProvider;

    @PostMapping("/login")
    // Nếu tham số là Json thì dùng @RequestBody
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest){

        // Hàm dùng để xác thực thông tin login (username/password)
        // Lấy username/password được truyền vào khi login
        // rồi so sánh với thông tin username/password ở UserService
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUserName(),
                        loginRequest.getPassword()));

        // Nếu không có exception nghĩa là hợp lệ (thông báo hợp lệ)
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Hợp lệ thì tạo Token, dùng jwtProvider.generateToken nhận vào
        // data muốn lưu vào Token (data kiểu GSon/String...)

        // Chỉ lưu UserName
        // String jwtToken = jwtProvider.generateToken(loginRequest.getUserName());

        // Lưu nguyên User
        String jwtToken = jwtProvider.generateToken((User) authentication.getPrincipal());
        return new ResponseEntity<String>(jwtToken, HttpStatus.OK);
    }

    @PostMapping("/test")
    public String test(){
        return "Test";
    }
}

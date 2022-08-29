package com.example.demologinjwt.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class UserService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<SimpleGrantedAuthority> roles = new ArrayList<SimpleGrantedAuthority>();
        SimpleGrantedAuthority roleAdmin = new SimpleGrantedAuthority("ROLE_ADMIN");
        roles.add(roleAdmin);

        // Tạo User luôn cần role
        // User mặc định của SS, tuy nhiên trong thực tế thì cần tạo một class userPojo (pojo) (để nhận giá tự queried từ DB)
        // Tạo tiếp class CustomUserDetails implements UserDetails chứa instance userPojo
        User user = new User("admin",
                "$2a$12$KLs3oadjXE0.8l2015vLdu5Uo2HElb2zazlBcF8gyCHEpEnCbJDzm", roles);
        return user;
    }
}

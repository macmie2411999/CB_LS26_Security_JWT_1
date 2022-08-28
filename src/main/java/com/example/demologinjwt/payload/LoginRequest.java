package com.example.demologinjwt.payload;

// Package payload: nơi tạo các tham số liên quan tới request/response
// đối với những APIs chưa hỗ trợ những request/response được khai báo sẵn từ Pojo/Entity

// Nếu dùng lombok thì không cần tạo getter/setter
public class LoginRequest {
    private String userName;
    private String password;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}

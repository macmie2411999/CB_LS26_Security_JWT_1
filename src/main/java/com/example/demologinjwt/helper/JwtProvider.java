package com.example.demologinjwt.helper;

import com.google.gson.Gson;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Date;

/* Mục đích của JwtProvider
* Khai báo hàm tạo token
* Giải mã token
* Kiểm tra token có phải do hệ thống sinh ra hay không
* */

// Đưa JwtProvider lên BEAN bằng annotation
@Component
public class JwtProvider {

    // Khai báo một Secret Key, mã hóa về kiểu base64
    private String SECRET_KEY = "YWRtaW4xMjM0NTY3ODkwQGFkbWluMTIzNDU2Nzg5MEBhZG1pbjEyMzQ1Njc4OTA=";
    // Mỗi Token phải có thời gian hết hạn (millisecond)
    private long JWT_EXPIRED = 8 * 60 * 60 * 1000;
    private Gson gson = new Gson();

    // Hàm khởi tạo token, nhận vào data muốn lưu vào Token (data kiểu GSon/String...)
    public String generateToken(String data){

        // Token hết hạn từ thời điểm được tạo ra + thời gian sống
        Date now = new Date();
        Date expiredDate = new Date(now.getTime() + JWT_EXPIRED);

        // Biến Object thành JSon
         String json = gson.toJson(data);

        return Jwts.builder()
                // Truyền data muốn lưu kèm ở Token vào
                .setSubject(data)
                // Thời gian tạo
                .setIssuedAt(now)
                // Thời gian hết hạn
                .setExpiration(expiredDate)
                // Nhận vào thuật mã hóa (quy chuẩn độ dài Secret Key) và Secret Key (mã hóa)
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                // Trả token (kiểu String)
                .compact();
    }

    // Hàm kiểm tra tính xác thực của Token truyền lên từ user
    // Giống hàm giải mã tuy nhiên không cần lấy giá trị giải mã
    public boolean validationToken(String token){
        try{
            // Do mỗi Token được tạo ra bằng một Secret Key cố định nên đòi hỏi cần chính xác Secret Key đấy để giải mã
            Jwts.parser().setSigningKey(SECRET_KEY)
                    // Truyền tham số Token cần validation
                    .parseClaimsJws(token);
            // Nếu hợp lệ
            return true;
        } catch (Exception e){
            // Nếu không hợp lệ
            return false;
        }
    }

    // Hàm validation luôn được sử dụng trước hàm decode (hợp lệ thì mới giải mã)
    // Hàm giải mã token, nhận vào token user truyền lên
    public String decodeToken(String token){
        return
                // Giải mã Token, truyền vào Secret Key ban đầu
                // Do mỗi Token được tạo ra bằng một Secret Key cố định
                // nên đòi hỏi cần chính xác Secret Key đấy để giải mã
                Jwts.parser().setSigningKey(SECRET_KEY)
                // Truyền tham số Token cần giải mã
                .parseClaimsJws(token)
                // Lấy giá trị yêu cầu
                .getBody().getSubject();
    }

}

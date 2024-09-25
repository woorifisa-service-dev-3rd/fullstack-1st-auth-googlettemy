package dev.auth.controller;

import org.apache.commons.codec.binary.Base32;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

@RestController
public class OtpResultController {

    @GetMapping("/verify-otp")
    public ResponseEntity<String> verifyOtp(
            @RequestParam String user_codeStr,
            @RequestParam String encodedKey) {

        long user_code = Long.parseLong(user_codeStr);
        long currentTime = new Date().getTime() / 30000;
        boolean isCodeValid = false;

        try {
            // OTP 일치 여부 확인
            isCodeValid = checkCode(encodedKey, user_code, currentTime);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            return ResponseEntity.status(500).body("OTP 검증 중 오류 발생");
        }

        // 일치 여부에 따라 응답 처리
        if (isCodeValid) {
            return ResponseEntity.ok("OTP가 유효합니다.");
        } else {
            return ResponseEntity.status(400).body("OTP가 유효하지 않습니다.");
        }
    }

    private static boolean checkCode(String secret, long code, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);

        // 과거 및 미래 시간 간격 허용
        int window = 3;
        for (int i = -window; i <= window; ++i) {
            long hash = verifyCode(decodedKey, t + i);

            if (hash == code) {
                return true;
            }
        }

        // OTP가 유효하지 않음
        return false;
    }

    private static int verifyCode(byte[] key, long t)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[20 - 1] & 0xF;

        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;

        return (int) truncatedHash;
    }
}


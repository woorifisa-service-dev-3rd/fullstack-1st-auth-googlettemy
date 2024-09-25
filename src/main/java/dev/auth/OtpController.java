package dev.auth;

import org.apache.commons.codec.binary.Base32;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

@RestController
@RequestMapping("/otp")
public class OtpController {

    @GetMapping("/generate")
    public String generateOtp(@RequestParam String user, @RequestParam String host) {
        // Allocating the buffer
        byte[] buffer = new byte[5 + 5 * 5];

        // Filling the buffer with random numbers.
        new Random().nextBytes(buffer);

        // Getting the key and converting it to Base32
        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 5 + 5 * 5);
        byte[] bEncodedKey = codec.encode(secretKey);

        // 생성된 Key
        String encodedKey = new String(bEncodedKey);

        // encodedKey만 반환
        return encodedKey;
    }

    @PostMapping("/verifyOtp")
    public boolean verifyOtp(@RequestParam String user_code, @RequestParam String encodedKey) {
        long userCode = Long.parseLong(user_code);
        long currentTimeIndex = new Date().getTime() / 30000; // 30초 단위로 시간 계산

        boolean isValid = false;
        try {
            // 키, 코드, 시간으로 일회용 비밀번호가 맞는지 일치 여부 확인
            isValid = checkCode(encodedKey, userCode, currentTimeIndex);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // 결과 반환
        return isValid;
    }

    private boolean checkCode(String secret, long code, long timeIndex) throws NoSuchAlgorithmException, InvalidKeyException {
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);

        // 최근에 생성된 코드 확인을 위한 윈도우 값
        int window = 3;
        for (int i = -window; i <= window; ++i) {
            long hash = verifyCode(decodedKey, timeIndex + i);
            if (hash == code) {
                return true; // 코드가 일치하는 경우
            }
        }
        return false; // 유효하지 않은 경우
    }

    private int verifyCode(byte[] key, long timeIndex) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = timeIndex;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[hash.length - 1] & 0xF; // 마지막 바이트에서 오프셋 추출
        long truncatedHash = 0;

        // 해시 결과에서 OTP 생성
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }

        truncatedHash &= 0x7FFFFFFF; // 부호 없는 정수로 변환
        truncatedHash %= 1000000; // 6자리 OTP
        return (int) truncatedHash;
    }
}


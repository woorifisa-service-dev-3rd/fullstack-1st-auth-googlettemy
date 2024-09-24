package dev.auth.controller;

import dev.auth.dto.OtpResponse;
import org.apache.commons.codec.binary.Base32;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Random;

@RestController
public class OtpController {

    @GetMapping("/generate-otp")
    public OtpResponse generateOtp(@RequestParam String user, @RequestParam String host) {
        byte[] buffer = new byte[5 + 5 * 5];
        new Random().nextBytes(buffer);

        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 5);
        byte[] bEncodedKey = codec.encode(secretKey);
        
        String encodedKey = new String(bEncodedKey);
        String url = getQRBarcodeURL(user, host, encodedKey);
        
        return new OtpResponse(encodedKey, url);
    }

    private String getQRBarcodeURL(String user, String host, String secret) {
        String format = "http://chart.apis.google.com/chart?cht=qr&chs=300x300&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&chld=H|0";
        return String.format(format, user, host, secret);
    }
}

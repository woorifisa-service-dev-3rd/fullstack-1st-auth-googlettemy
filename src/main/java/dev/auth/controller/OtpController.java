package dev.auth.controller;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import org.apache.commons.codec.binary.Base32;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

@RestController
public class OtpController {

    // 1. QR 코드 URL을 생성하여 반환하는 API
    @GetMapping("/generate-otp")
    public ResponseEntity<String> generateOtp(@RequestParam String user, @RequestParam String host) {
        byte[] buffer = new byte[5 + 5 * 5];
        new Random().nextBytes(buffer);

        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 5 + 5 * 5);
        byte[] bEncodedKey = codec.encode(secretKey);

        String encodedKey = new String(bEncodedKey);

        // /qr-code로 이동하여 QR 코드 이미지 보기
        String url = String.format("http://localhost:8080/qr-code?user=%s&host=%s&secret=%s", user, host, encodedKey);

        return ResponseEntity.ok(encodedKey + '\n' + url);
    }

    // 2. URL로 접속하면 QR 코드를 이미지로 서빙하는 엔드포인트
    @GetMapping("/qr-code")
    public ResponseEntity<byte[]> getQRCodeImage(@RequestParam String user, @RequestParam String host, @RequestParam String secret) throws WriterException, IOException {
        String qrCodeData = String.format("otpauth://totp/%s@%s?secret=%s", user, host, secret);

        ByteArrayOutputStream qrStream = createQRCode(qrCodeData, 300, 300);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_PNG);

        // QR 코드 이미지 반환
        return ResponseEntity.ok().headers(headers).body(qrStream.toByteArray());
    }

    private ByteArrayOutputStream createQRCode(String qrCodeData, int width, int height) throws WriterException, IOException {
        BitMatrix matrix = new MultiFormatWriter().encode(qrCodeData, BarcodeFormat.QR_CODE, width, height);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", outputStream);
        return outputStream;
    }
}

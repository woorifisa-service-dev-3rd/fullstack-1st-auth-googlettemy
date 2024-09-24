package dev.auth.dto;

import lombok.Getter;

@Getter
public class OtpResponse {
    private String encodedKey;
    private String url;

    public OtpResponse(String encodedKey, String url) {
        this.encodedKey = encodedKey;
        this.url = url;
    }
}

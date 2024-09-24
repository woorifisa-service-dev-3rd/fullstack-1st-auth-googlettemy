package dev.auth.dto;

public class OtpResponse {
    private String encodedKey;
    private String url;

    public OtpResponse(String encodedKey, String url) {
        this.encodedKey = encodedKey;
        this.url = url;
    }

    public String getEncodedKey() {
        return encodedKey;
    }

    public String getUrl() {
        return url;
    }
}

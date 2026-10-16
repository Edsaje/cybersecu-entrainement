package com.devfolio.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URL;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class AvatarController {

    @PostMapping("/avatar")
    public ResponseEntity<?> setAvatarFromUrl(
            @RequestParam String url,
            @RequestHeader(value = "Authorization", required = false) String token) throws Exception {

        URL avatarUrl = new URL(url);
        byte[] imageData = avatarUrl.openStream().readAllBytes();

        // Sauvegarde et retourne l'image fetchée
        String base64 = Base64.getEncoder().encodeToString(imageData);
        return ResponseEntity.ok(Map.of("avatar", "data:image/png;base64," + base64));
    }
}

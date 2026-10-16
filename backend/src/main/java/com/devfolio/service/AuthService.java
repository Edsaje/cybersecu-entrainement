package com.devfolio.service;

import com.devfolio.model.User;
import com.devfolio.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User register(String email, String password) {
        // Remplacement du MD5 par BCrypt
        String hashedPassword = passwordEncoder.encode(password);

        // Suppression du log du mot de passe en clair (VULN-09)
        log.info("Registering user: {}", email);

        User user = new User();
        user.setEmail(email);
        user.setPassword(hashedPassword);
        user.setRole("USER");
        return userRepository.save(user);
    }
}

package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    @Transactional
    public User syncOrCreateUser(UUID keycloakSub, String email, boolean isEmailVerified) {
        return userRepository.findByKeycloakSub(keycloakSub)
            .map(existingUser -> {
                if (isEmailVerified && email != null && !email.equals(existingUser.getEmail())) {
                    existingUser.setEmail(email);
                }
                return existingUser;
            })
            .orElseGet(() -> {
                try {
                    User user = new User();
                    user.setKeycloakSub(keycloakSub);
                    user.setEmail(isEmailVerified ? email : null);
                    return userRepository.save(user);
                } catch (DataIntegrityViolationException e) {
                    return userRepository.findByKeycloakSub(keycloakSub)
                        .orElseThrow(() ->
                            new IllegalStateException("User missing after unique constraint violation")
                        );
                }
            });
    }
}

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
    public User syncOrCreateUser(UUID authId, String email, boolean isEmailVerified) {
        return userRepository.findByAuthId(authId)
            .map(existingUser -> {
                if (isEmailVerified && email != null && !email.equals(existingUser.getEmail())) {
                    existingUser.setEmail(email);
                }
                return existingUser;
            })
            .orElseGet(() -> {
                try {
                    User user = new User();
                    user.setAuthId(authId);
                    user.setEmail(isEmailVerified ? email : null);
                    return userRepository.save(user);
                } catch (DataIntegrityViolationException e) {
                    return userRepository.findByAuthId(authId)
                        .orElseThrow(() ->
                            new IllegalStateException("User missing after unique constraint violation")
                        );
                }
            });
    }
}

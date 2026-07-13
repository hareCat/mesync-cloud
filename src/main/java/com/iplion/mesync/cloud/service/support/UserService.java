package com.iplion.mesync.cloud.service.support;

import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.api.UpdateMasterKeyVersionException;
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
    public User syncOrCreateUser(UUID authId, String email, boolean emailVerified) {
        return userRepository.findByAuthId(authId)
            .map(existingUser -> {
                String newEmail = resolveEmailUpdate(email, emailVerified, existingUser.getEmail());

                if (newEmail != null) {
                    existingUser.setEmail(newEmail);
                }

                return existingUser;
            })
            .orElseGet(() -> {
                try {
                    User user = new User();
                    user.setAuthId(authId);
                    user.setEmail(resolveEmailUpdate(email, emailVerified, null));
                    return userRepository.save(user);
                } catch (DataIntegrityViolationException e) {
                    return userRepository.findByAuthId(authId)
                        .orElseThrow(() ->
                            new IllegalStateException("User missing after unique constraint violation")
                        );
                }
            });
    }

    @Transactional
    public void updateMasterKeyVersion(User user, int newMasterKeyVersion) {
        if (newMasterKeyVersion != user.getKeyVersion() + 1) {
            throw new UpdateMasterKeyVersionException(String.format(
                "Master key version does not match expected. userKeyVersion: %d, newKeyVersion: %d",
                user.getKeyVersion(),
                newMasterKeyVersion
            ));
        }

        user.setKeyVersion(newMasterKeyVersion);

        userRepository.save(user);
    }

    private String resolveEmailUpdate(String email, boolean emailVerified, String oldEmail) {
        if (!emailVerified || email == null || email.isBlank()) {
            return null;
        }

        String normalizedEmail = email.trim();
        return normalizedEmail.equals(oldEmail) ? null : normalizedEmail;
    }

}

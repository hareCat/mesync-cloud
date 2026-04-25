package com.iplion.mesync.cloud.service;

import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {
    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Test
    public void syncOrCreateUser_whenNewEmailVerified_shouldReturnExistingUserWithUpdatedEmail() {
        UUID authId = UUID.randomUUID();
        String oldEmail = "oldEmail";
        String newEmail = "newEmail";

        User user = new User();
        user.setAuthId(authId);
        user.setEmail(oldEmail);

        when(userRepository.findByAuthId(any(UUID.class))).thenReturn(Optional.of(user));

        var result = userService.syncOrCreateUser(authId, newEmail, true);

        assertThat(result.getAuthId()).isEqualTo(user.getAuthId());
        assertThat(result.getEmail()).isEqualTo(newEmail);
    }

    @Test
    public void syncOrCreateUser_whenNewEmailNotVerifiedOrNullOrSame_shouldReturnExistingUserWithOldEmail() {
        UUID authId = UUID.randomUUID();
        String oldEmail = "oldEmail";
        String newEmail = "newEmail";

        User user = new User();
        user.setAuthId(authId);
        user.setEmail(oldEmail);

        when(userRepository.findByAuthId(any(UUID.class))).thenReturn(Optional.of(user));

        var result = userService.syncOrCreateUser(authId, newEmail, false);
        assertThat(result.getAuthId()).isEqualTo(user.getAuthId());
        assertThat(result.getEmail()).isEqualTo(oldEmail);

        result = userService.syncOrCreateUser(authId, null, true);
        assertThat(result.getAuthId()).isEqualTo(user.getAuthId());
        assertThat(result.getEmail()).isEqualTo(oldEmail);

        result = userService.syncOrCreateUser(authId, oldEmail, true);
        assertThat(result.getAuthId()).isEqualTo(user.getAuthId());
        assertThat(result.getEmail()).isEqualTo(oldEmail);
    }

    @Test
    public void syncOrCreateUser_whenUserSavingError_shouldThrowIllegalStateException() {
        when(userRepository.findByAuthId(any(UUID.class))).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenThrow(new DataIntegrityViolationException("error"));

        assertThatThrownBy(() -> userService.syncOrCreateUser(UUID.randomUUID(), "email", true))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    public void syncOrCreateUser_whenUserNotExists_createsNewUser() {
        UUID authId = UUID.randomUUID();
        String email = "email";

        User user = new User();
        user.setAuthId(authId);
        user.setEmail(email);

        when(userRepository.findByAuthId(any(UUID.class))).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenReturn(user);

        var result = userService.syncOrCreateUser(authId, email, true);

        assertThat(result.getAuthId()).isEqualTo(user.getAuthId());
        assertThat(result.getEmail()).isEqualTo(email);
    }

    @Test
    void syncOrCreateUser_whenConcurrentInsert_shouldReturnExistingUser() {
        UUID authId = UUID.randomUUID();
        String email = "email";

        User existing = new User();
        existing.setAuthId(authId);
        existing.setEmail(email);

        when(userRepository.findByAuthId(any(UUID.class)))
            .thenReturn(Optional.empty())
            .thenReturn(Optional.of(existing));

        when(userRepository.save(any()))
            .thenThrow(new DataIntegrityViolationException("error"));

        var result = userService.syncOrCreateUser(authId, email, true);

        assertThat(result).isEqualTo(existing);
    }

}

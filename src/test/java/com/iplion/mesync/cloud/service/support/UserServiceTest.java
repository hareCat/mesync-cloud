package com.iplion.mesync.cloud.service.support;

import com.iplion.mesync.cloud.BaseUnitTest;
import com.iplion.mesync.cloud.entity.User;
import com.iplion.mesync.cloud.error.api.UpdateMasterKeyVersionException;
import com.iplion.mesync.cloud.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class UserServiceTest extends BaseUnitTest {
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
    public void syncOrCreateUser_whenExistingEmailHasWhitespace_shouldReturnExistingUserWithTrimmedEmail() {
        UUID authId = UUID.randomUUID();
        String email = "email";

        User user = new User();
        user.setAuthId(authId);
        user.setEmail("  " + email + "  ");

        when(userRepository.findByAuthId(any(UUID.class))).thenReturn(Optional.of(user));

        var result = userService.syncOrCreateUser(authId, email, true);

        assertThat(result.getAuthId()).isEqualTo(user.getAuthId());
        assertThat(result.getEmail()).isEqualTo(email);
    }

    @ParameterizedTest
    @CsvSource(value = {
        "newEmail, false",
        "NULL, true",
        "'', true",
        "'   ', true",
        "oldEmail, true"
    }, nullValues = "NULL")
    public void syncOrCreateUser_whenEmailShouldNotBeUpdated_shouldReturnExistingUserWithOldEmail(
        String newEmail,
        boolean emailVerified
    ) {
        UUID authId = UUID.randomUUID();
        String oldEmail = "oldEmail";

        User user = new User();
        user.setAuthId(authId);
        user.setEmail(oldEmail);

        when(userRepository.findByAuthId(any(UUID.class))).thenReturn(Optional.of(user));

        var result = userService.syncOrCreateUser(authId, newEmail, emailVerified);
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

    @Test
    void updateMasterKeyVersion_shouldUpdateMasterKeyVersion() {
        int currentMasterKeyVersion = 1;
        int newMasterKeyVersion = 2;

        User user = new User();
        user.setKeyVersion(currentMasterKeyVersion);

        userService.updateMasterKeyVersion(user, newMasterKeyVersion);

        assertThat(user.getKeyVersion()).isEqualTo(newMasterKeyVersion);

        verify(userRepository).save(user);
    }

    @Test
    void updateMasterKeyVersion_shouldThrown_whenNewKeyVersionInvalid() {
        int currentMasterKeyVersion = 1;
        int newMasterKeyVersion = 3;

        User user = new User();
        user.setKeyVersion(currentMasterKeyVersion);

        assertThatThrownBy(() -> userService.updateMasterKeyVersion(user, newMasterKeyVersion))
            .isInstanceOf(UpdateMasterKeyVersionException.class);

        verifyNoInteractions(userRepository);
    }

}

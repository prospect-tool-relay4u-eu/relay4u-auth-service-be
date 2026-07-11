package eu.relay4u.authservicebe.security;

import eu.relay4u.authservicebe.model.User;
import eu.relay4u.authservicebe.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock UserRepository userRepository;

    @InjectMocks CustomUserDetailsService customUserDetailsService;

    @Test
    void loadUserByUsername_returnsUser_whenEmailExists() {
        User user = new User();
        user.setEmail("jane@example.com");
        when(userRepository.findUserByEmail("jane@example.com")).thenReturn(Optional.of(user));

        UserDetails result = customUserDetailsService.loadUserByUsername("jane@example.com");

        assertThat(result).isSameAs(user);
    }

    @Test
    void loadUserByUsername_throwsUsernameNotFoundException_whenEmailUnknown() {
        when(userRepository.findUserByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername("missing@example.com"))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}

package eu.relay4u.authservicebe.service.email;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@Profile("sandbox")
public class LoggingEmailService implements EmailService {

    @Override
    public void sendVerificationCode(String toEmail, String recipientName, String code) {
        log.info("[SANDBOX] Verification code for {} ({}): {}", toEmail, recipientName, code);
    }
}

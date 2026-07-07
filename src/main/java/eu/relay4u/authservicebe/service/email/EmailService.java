package eu.relay4u.authservicebe.service.email;

public interface EmailService {
    void sendVerificationCode(String toEmail, String recipientName, String code);
}

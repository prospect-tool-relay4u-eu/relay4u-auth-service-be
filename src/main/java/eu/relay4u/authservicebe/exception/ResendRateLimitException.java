package eu.relay4u.authservicebe.exception;

public class ResendRateLimitException extends RuntimeException {
    public ResendRateLimitException(String message) {
        super(message);
    }
}

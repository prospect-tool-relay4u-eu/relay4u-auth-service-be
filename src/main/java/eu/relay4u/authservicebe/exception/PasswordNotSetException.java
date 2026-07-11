package eu.relay4u.authservicebe.exception;

import lombok.Getter;

@Getter
public class PasswordNotSetException extends RuntimeException {
    private final String email;
    private final String name;

    public PasswordNotSetException(String email, String name) {
        super("Password not set. Please complete registration.");
        this.email = email;
        this.name = name;
    }
}

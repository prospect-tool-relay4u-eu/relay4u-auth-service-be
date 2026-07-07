package eu.relay4u.authservicebe.exception;

public class ProjectNotFoundException extends RuntimeException {
    public ProjectNotFoundException() {
        super("Project not found");
    }
}

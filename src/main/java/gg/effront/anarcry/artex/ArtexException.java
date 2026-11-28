package gg.effront.anarcry.artex;

/** Thrown when an ARTEX API call fails. */
public class ArtexException extends RuntimeException {

    private final int statusCode;
    private final String responseBody;

    public ArtexException(String message, int statusCode, String responseBody) {
        super(message);
        this.statusCode = statusCode;
        this.responseBody = responseBody;
    }

    public ArtexException(String message, Throwable cause) {
        super(message, cause);
        this.statusCode = -1;
        this.responseBody = "";
    }

    public int statusCode() {
        return statusCode;
    }

    public String responseBody() {
        return responseBody;
    }

    @Override
    public String toString() {
        if (statusCode > 0) {
            return "ArtexException{status=" + statusCode + ", message=" + getMessage() + "}";
        }
        return "ArtexException{message=" + getMessage() + "}";
    }
}

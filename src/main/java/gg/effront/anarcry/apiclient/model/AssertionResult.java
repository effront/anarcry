package gg.effront.anarcry.apiclient.model;

public record AssertionResult(Assertion assertion, boolean passed, String actual, String message) {

    public static AssertionResult pass(Assertion assertion, String actual) {
        return new AssertionResult(assertion, true, actual, "");
    }

    public static AssertionResult fail(Assertion assertion, String actual, String message) {
        return new AssertionResult(assertion, false, actual, message);
    }
}

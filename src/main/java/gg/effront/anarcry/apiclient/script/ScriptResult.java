package gg.effront.anarcry.apiclient.script;

import java.util.List;

public record ScriptResult(List<String> consoleLog, List<TestResult> testResults, String error) {

    public record TestResult(String name, boolean passed, String message) {
    }

    public ScriptResult {
        if (consoleLog == null) {
            consoleLog = List.of();
        }
        if (testResults == null) {
            testResults = List.of();
        }
    }

    public static ScriptResult empty() {
        return new ScriptResult(List.of(), List.of(), null);
    }

    public static ScriptResult ofError(String error) {
        return new ScriptResult(List.of(), List.of(), error);
    }

    public boolean hasError() {
        return error != null && !error.isEmpty();
    }

    public int testsPassed() {
        return (int) testResults.stream().filter(TestResult::passed).count();
    }

    public int testsFailed() {
        return (int) testResults.stream().filter(t -> !t.passed()).count();
    }
}

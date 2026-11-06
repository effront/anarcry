package gg.effront.anarcry.apiclient.model;

public record Assertion(String lhs, AssertOp op, String rhs, boolean enabled) {

    public Assertion {
        if (lhs == null) {
            lhs = "";
        }
        if (op == null) {
            op = AssertOp.EQ;
        }
    }

    public static Assertion of(String lhs, AssertOp op, String rhs) {
        return new Assertion(lhs, op, rhs, true);
    }
}

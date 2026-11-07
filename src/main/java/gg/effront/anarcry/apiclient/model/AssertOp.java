package gg.effront.anarcry.apiclient.model;

import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum AssertOp {

    EQ("eq"), NEQ("neq"), GT("gt"), GTE("gte"), LT("lt"), LTE("lte"), IN("in"), NOT_IN("notIn"), CONTAINS(
            "contains"), NOT_CONTAINS("notContains"), LENGTH("length"), MATCHES("matches"), NOT_MATCHES(
                    "notMatches"), STARTS_WITH("startsWith"), ENDS_WITH("endsWith"), BETWEEN("between"), IS_NULL(
                            "isNull"), IS_UNDEFINED("isUndefined"), IS_DEFINED("isDefined"), IS_TRUTHY(
                                    "isTruthy"), IS_FALSY("isFalsy"), IS_JSON("isJson"), IS_NUMBER(
                                            "isNumber"), IS_STRING("isString"), IS_BOOLEAN("isBoolean"), IS_ARRAY(
                                                    "isArray"), IS_EMPTY("isEmpty"), IS_NOT_EMPTY("isNotEmpty");

    private static final Map<String, AssertOp> BY_SYMBOL = Stream.of(values())
            .collect(Collectors.toUnmodifiableMap(AssertOp::symbol, op -> op));

    private final String symbol;

    AssertOp(String symbol) {
        this.symbol = symbol;
    }

    public String symbol() {
        return symbol;
    }

    public boolean isUnary() {
        return ordinal() >= IS_NULL.ordinal();
    }

    public static AssertOp fromSymbol(String symbol) {
        AssertOp op = BY_SYMBOL.get(symbol);
        if (op == null) {
            throw new IllegalArgumentException("Unknown assertion operator: " + symbol);
        }
        return op;
    }
}

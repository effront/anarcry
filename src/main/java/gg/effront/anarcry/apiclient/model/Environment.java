package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record Environment(String uid, String name, String color, List<EnvVariable> variables, String extendsEnv) {

    public Environment {
        if (uid == null) {
            uid = "";
        }
        if (name == null) {
            name = "";
        }
        if (variables == null) {
            variables = List.of();
        }
    }

    public static Environment of(String name, List<EnvVariable> variables) {
        return new Environment(java.util.UUID.randomUUID().toString(), name, null, variables, null);
    }
}

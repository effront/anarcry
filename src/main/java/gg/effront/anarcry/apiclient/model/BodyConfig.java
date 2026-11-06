package gg.effront.anarcry.apiclient.model;

import java.util.List;

public sealed interface BodyConfig {

    String mode();

    record None() implements BodyConfig {

        @Override
        public String mode() {
            return "none";
        }
    }

    record Json(String content) implements BodyConfig {

        @Override
        public String mode() {
            return "json";
        }
    }

    record Text(String content) implements BodyConfig {

        @Override
        public String mode() {
            return "text";
        }
    }

    record Xml(String content) implements BodyConfig {

        @Override
        public String mode() {
            return "xml";
        }
    }

    record FormUrlEncoded(List<Param> params) implements BodyConfig {

        @Override
        public String mode() {
            return "formUrlEncoded";
        }
    }

    record MultipartForm(List<MultipartField> fields) implements BodyConfig {

        @Override
        public String mode() {
            return "multipartForm";
        }
    }

    record GraphQL(String query, String variables) implements BodyConfig {

        @Override
        public String mode() {
            return "graphql";
        }
    }

    record FileBody(String filePath, String contentType) implements BodyConfig {

        @Override
        public String mode() {
            return "file";
        }
    }

    record MultipartField(String name, String value, String type, String filePath, String contentType,
            boolean enabled) {
    }
}

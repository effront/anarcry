package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record Collection(String uid, String name, String version, List<Environment> environments,
        List<CollectionItem> items, RootConfig root, CollectionSettings settings) {

    public Collection {
        if (uid == null) {
            uid = java.util.UUID.randomUUID().toString();
        }
        if (name == null) {
            name = "";
        }
        if (version == null) {
            version = "1";
        }
        if (environments == null) {
            environments = List.of();
        }
        if (items == null) {
            items = List.of();
        }
        if (root == null) {
            root = RootConfig.empty();
        }
        if (settings == null) {
            settings = CollectionSettings.defaults();
        }
    }
}

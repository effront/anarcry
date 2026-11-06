package gg.effront.anarcry.apiclient.model;

import java.util.List;

public record Folder(String uid, String name, List<CollectionItem> items, RootConfig root) implements CollectionItem {

    public Folder {
        if (uid == null) {
            uid = java.util.UUID.randomUUID().toString();
        }
        if (name == null) {
            name = "";
        }
        if (items == null) {
            items = List.of();
        }
        if (root == null) {
            root = RootConfig.empty();
        }
    }
}

package gg.effront.anarcry.apiclient.model;

public sealed interface CollectionItem permits Folder, RequestItem {

    String uid();

    String name();
}

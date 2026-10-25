package gg.effront.anarcry.model;

public record Suppression(String module, String titleContains, String reason, String date, String target) {

    public Suppression {
        if (module == null) {
            module = "";
        }
        if (titleContains == null) {
            titleContains = "";
        }
        if (reason == null) {
            reason = "";
        }
        if (date == null) {
            date = "";
        }
        if (target == null) {
            target = "";
        }
    }

    public boolean matches(String findingModule, String findingTitle, String findingHost) {
        boolean moduleMatch = module.isBlank() || module.equalsIgnoreCase(findingModule);
        boolean titleMatch = titleContains.isBlank()
                || findingTitle.toLowerCase().contains(titleContains.toLowerCase());
        boolean hostMatch = target.isBlank() || findingHost.toLowerCase().contains(target.toLowerCase());
        return moduleMatch && titleMatch && hostMatch;
    }
}

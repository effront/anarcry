package gg.effront.anarcry.apiclient.script;

import gg.effront.anarcry.apiclient.vars.VariableStore;

import org.graalvm.polyglot.HostAccess;

public class BruBridge {

    private final VariableStore vars;

    public BruBridge(VariableStore vars) {
        this.vars = vars;
    }

    @HostAccess.Export
    public String getVar(String key) {
        return vars.resolve(key);
    }

    @HostAccess.Export
    public void setVar(String key, String value) {
        vars.setRuntime(key, value);
    }

    @HostAccess.Export
    public String getEnvVar(String key) {
        String v = vars.envVars().get(key);
        return v != null ? v : "";
    }

    @HostAccess.Export
    public void setEnvVar(String key, String value) {
        vars.setRuntime(key, value);
    }

    @HostAccess.Export
    public String getCollectionVar(String key) {
        String v = vars.collectionVars().get(key);
        return v != null ? v : "";
    }

    @HostAccess.Export
    public String getFolderVar(String key) {
        String v = vars.folderVars().get(key);
        return v != null ? v : "";
    }

    @HostAccess.Export
    public String getRequestVar(String key) {
        String v = vars.requestVars().get(key);
        return v != null ? v : "";
    }

    @HostAccess.Export
    public String getProcessEnv(String key) {
        String v = System.getenv(key);
        return v != null ? v : "";
    }
}

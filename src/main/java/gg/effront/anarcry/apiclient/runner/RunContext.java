package gg.effront.anarcry.apiclient.runner;

import gg.effront.anarcry.apiclient.model.RequestResult;
import gg.effront.anarcry.apiclient.script.ScriptResult;
import gg.effront.anarcry.apiclient.vars.VariableStore;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class RunContext {

    private final VariableStore vars;
    private final CookieManager cookieManager;
    private final List<RequestResult> results;
    private final AtomicBoolean cancel;
    private volatile boolean stopRequested;
    private volatile String nextRequest;
    private volatile ScriptResult lastScriptResult;

    public RunContext(VariableStore vars) {
        this.vars = vars;
        this.cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        this.results = new ArrayList<>();
        this.cancel = new AtomicBoolean(false);
    }

    public VariableStore vars() {
        return vars;
    }

    public CookieManager cookieManager() {
        return cookieManager;
    }

    public List<RequestResult> results() {
        return results;
    }

    public void requestStop() {
        stopRequested = true;
    }

    public boolean shouldStop() {
        return stopRequested || cancel.get();
    }

    public void cancel() {
        cancel.set(true);
    }

    public boolean isCancelled() {
        return cancel.get();
    }

    public void setNextRequest(String name) {
        this.nextRequest = name;
    }

    public String nextRequest() {
        return nextRequest;
    }

    public void clearNextRequest() {
        this.nextRequest = null;
    }

    public void setLastScriptResult(ScriptResult result) {
        this.lastScriptResult = result;
    }

    public ScriptResult lastScriptResult() {
        return lastScriptResult;
    }
}

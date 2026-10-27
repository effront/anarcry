package gg.effront.anarcry.tui.chrome;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

public class StatusBar extends Panel {

    private static final String[] DOTS = {"", ".", "..", "..."};

    private final Label label;

    private String target = "";
    private int critCount = 0;
    private int highCount = 0;
    private int medCount = 0;
    private int lowCount = 0;
    private int modDone = 0;
    private int modTotal = 0;
    private final Set<String> activeModules = new LinkedHashSet<>();
    private final Map<String, Long> moduleStartTimes = new LinkedHashMap<>();
    private final List<String> completedModules = new ArrayList<>();
    private int dotFrame = 0;
    private Consumer<Runnable> guiInvoker;
    private Runnable onExpandRequest;

    private final ScheduledExecutorService animator = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "statusbar-anim");
        t.setDaemon(true);
        return t;
    });
    private ScheduledFuture<?> animTask;

    public StatusBar() {
        super(new LinearLayout(Direction.HORIZONTAL));
        label = new Label(" ");
        label.setForegroundColor(TextColor.ANSI.BLACK);
        label.setBackgroundColor(TextColor.ANSI.WHITE_BRIGHT);
        addComponent(label, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
        refresh();
    }

    public void setGuiInvoker(Consumer<Runnable> invoker) {
        this.guiInvoker = invoker;
    }

    public void setOnExpandRequest(Runnable handler) {
        this.onExpandRequest = handler;
    }

    public void expandProgress() {
        if (onExpandRequest != null) {
            onExpandRequest.run();
        }
    }

    public void setTarget(String target) {
        this.target = target == null ? "" : target;
        refresh();
    }

    public void setSeverityCounts(int crit, int high, int med, int low) {
        this.critCount = crit;
        this.highCount = high;
        this.medCount = med;
        this.lowCount = low;
        refresh();
    }

    public void setModuleProgress(int done, int total) {
        this.modDone = done;
        this.modTotal = total;
        refresh();
    }

    public void moduleStarted(String moduleId) {
        activeModules.add(moduleId);
        moduleStartTimes.put(moduleId, System.currentTimeMillis());
        dotFrame = 0;
        startAnimation();
        refresh();
    }

    public void moduleDone(String moduleId) {
        activeModules.remove(moduleId);
        moduleStartTimes.remove(moduleId);
        completedModules.add(moduleId);
        if (activeModules.isEmpty()) {
            stopAnimation();
        }
        refresh();
    }

    public void scanDone() {
        activeModules.clear();
        moduleStartTimes.clear();
        completedModules.clear();
        stopAnimation();
        refresh();
    }

    public void dumpModuleStatus(Consumer<String> log) {
        if (modTotal == 0) {
            log.accept("[*] Nenhum scan em andamento");
            return;
        }
        long now = System.currentTimeMillis();
        if (!completedModules.isEmpty()) {
            log.accept("[+] Concluidos (" + completedModules.size() + "): " + String.join(", ", completedModules));
        }
        if (!activeModules.isEmpty()) {
            for (String mod : activeModules) {
                Long started = moduleStartTimes.get(mod);
                String elapsed = started != null ? " (" + ((now - started) / 1000) + "s)" : "";
                log.accept("[~] Rodando: " + mod + elapsed);
            }
        }
        int pending = modTotal - modDone - activeModules.size();
        if (pending > 0) {
            log.accept("[*] Pendentes: " + pending + " modulo(s)");
        }
        log.accept("[*] Progresso: " + modDone + "/" + modTotal);
    }

    private void startAnimation() {
        if (animTask != null && !animTask.isCancelled()) {
            return;
        }
        animTask = animator.scheduleAtFixedRate(() -> {
            dotFrame = (dotFrame + 1) % DOTS.length;
            if (guiInvoker != null) {
                guiInvoker.accept(this::refresh);
            }
        }, 400, 400, TimeUnit.MILLISECONDS);
    }

    private void stopAnimation() {
        if (animTask != null) {
            animTask.cancel(false);
            animTask = null;
        }
        dotFrame = 0;
    }

    private void refresh() {
        String alvo = target.isBlank() ? "sem alvo" : target;
        if (alvo.length() > 50) {
            alvo = "..." + alvo.substring(alvo.length() - 47);
        }
        String progress = "";
        if (modTotal > 0) {
            int w = 12;
            int filled = (int) Math.round((double) modDone / modTotal * w);
            String bar = "█".repeat(filled) + "░".repeat(w - filled);
            progress = " │ [" + bar + "] " + modDone + "/" + modTotal;
        }
        String activity = "";
        if (!activeModules.isEmpty()) {
            String names = String.join(", ", activeModules);
            if (names.length() > 30) {
                names = names.substring(0, 27) + "...";
            }
            activity = " │ " + names + DOTS[dotFrame];
        }
        label.setText(String.format(" alvo: %s │ ◆%d ▲%d ●%d ▼%d%s%s │ [Q] Sair  [E] Export  [?] Ações ", alvo,
                critCount, highCount, medCount, lowCount, progress, activity));
    }
}

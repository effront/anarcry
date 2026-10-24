package gg.effront.anarcry.tui.chrome;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.*;

public class StatusBar extends Panel {

    private final Label label;

    private String target      = "";
    private int    critCount   = 0;
    private int    highCount   = 0;
    private int    medCount    = 0;
    private int    lowCount    = 0;
    private int    modDone     = 0;
    private int    modTotal    = 0;

    public StatusBar() {
        super(new LinearLayout(Direction.HORIZONTAL));
        label = new Label(" ");
        label.setForegroundColor(TextColor.ANSI.BLACK);
        label.setBackgroundColor(TextColor.ANSI.WHITE_BRIGHT);
        addComponent(label, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));
        refresh();
    }

    public void setTarget(String target) {
        this.target = target == null ? "" : target;
        refresh();
    }

    public void setSeverityCounts(int crit, int high, int med, int low) {
        this.critCount = crit;
        this.highCount = high;
        this.medCount  = med;
        this.lowCount  = low;
        refresh();
    }

    public void setModuleProgress(int done, int total) {
        this.modDone  = done;
        this.modTotal = total;
        refresh();
    }

    private void refresh() {
        String alvo = target.isBlank() ? "sem alvo" : target;
        if (alvo.length() > 50) alvo = "..." + alvo.substring(alvo.length() - 47);
        String progress = "";
        if (modTotal > 0) {
            int w      = 12;
            int filled = (int) Math.round((double) modDone / modTotal * w);
            String bar = "█".repeat(filled) + "░".repeat(w - filled);
            progress   = " │ [" + bar + "] " + modDone + "/" + modTotal;
        }
        label.setText(String.format(
                " alvo: %s │ ◆%d ▲%d ●%d ▼%d%s │ [Q] Sair  [E] Export  [?] Ações ",
                alvo, critCount, highCount, medCount, lowCount, progress));
    }
}

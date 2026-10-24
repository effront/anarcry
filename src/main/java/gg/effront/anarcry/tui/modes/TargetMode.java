package gg.effront.anarcry.tui.modes;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Component;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import gg.effront.anarcry.tui.PasteableTextBox;
import gg.effront.anarcry.tui.panels.ModulesPanel;

public class TargetMode {

    public static Component build(ModulesPanel modulesPanel, Runnable onApply) {
        var p = new Panel(new LinearLayout(Direction.VERTICAL));

        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        addField(p, "Host / URL completa:");
        var hostBox = new PasteableTextBox(new TerminalSize(60, 1));
        hostBox.setText(modulesPanel.getTarget());
        p.addComponent(hostBox);

        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        addField(p, "JWT Token (User 1):");
        var jwtBox = new PasteableTextBox(new TerminalSize(60, 2));
        jwtBox.setText(modulesPanel.getJwt());
        p.addComponent(jwtBox);

        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        Label status = new Label("");
        status.setForegroundColor(TextColor.ANSI.GREEN);

        var buttons = new Panel(new LinearLayout(Direction.HORIZONTAL));
        buttons.addComponent(new Button("Definir como alvo  [Enter]", () -> {
            String host = hostBox.getText().trim();
            if (host.isBlank()) {
                status.setText("  [!] URL não pode estar vazio");
                status.setForegroundColor(TextColor.ANSI.YELLOW);
                return;
            }
            modulesPanel.setTarget(host);
            modulesPanel.setJwt(jwtBox.getText().trim());
            onApply.run();
        }));
        p.addComponent(buttons);

        p.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        p.addComponent(status);

        Label hint = new Label("  Pressione Enter no botão ou F2 para voltar ao scan.");
        hint.setForegroundColor(TextColor.ANSI.WHITE);
        p.addComponent(hint);

        return p.withBorder(Borders.singleLine("Target"));
    }

    private static void addField(Panel p, String label) {
        Label lbl = new Label("  " + label);
        lbl.setForegroundColor(TextColor.ANSI.BLUE);
        p.addComponent(lbl);
    }
}

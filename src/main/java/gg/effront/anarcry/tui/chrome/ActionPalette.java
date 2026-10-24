package gg.effront.anarcry.tui.chrome;

import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.*;

import java.util.List;
import java.util.Set;

public class ActionPalette {

    private static final List<String[]> ACTIONS = List.of(
        new String[]{"F1", "Modo SCAN — painel de módulos e log"},
        new String[]{"F2", "Modo FINDINGS — tabela de achados"},
        new String[]{"F3", "Modo DASHBOARD — resumo da sessão"},
        new String[]{"F4", "Modo REPEATER — requisição/resposta"},
        new String[]{"F5", "Modo NOTES — bloco de anotações"},
        new String[]{"F6", "Modo RELATÓRIO — exportar JSON/MD"},
        new String[]{"?",  "Abrir este painel de ações"},
        new String[]{"q",  "Sair da aplicação"}
    );

    public static void show(WindowBasedTextGUI gui) {
        BasicWindow dialog = new BasicWindow("Ações — AnarCry");
        dialog.setHints(Set.of(Window.Hint.CENTERED, Window.Hint.MODAL));

        Panel panel = new Panel(new GridLayout(2));
        GridLayout gl = (GridLayout) panel.getLayoutManager();
        gl.setHorizontalSpacing(3);

        for (String[] row : ACTIONS) {
            panel.addComponent(new Label(row[0])
                    .setForegroundColor(TextColor.ANSI.YELLOW));
            panel.addComponent(new Label(row[1]));
        }

        panel.addComponent(new EmptySpace());
        panel.addComponent(new Button("Fechar", dialog::close)
                .setLayoutData(GridLayout.createLayoutData(
                        GridLayout.Alignment.END, GridLayout.Alignment.CENTER)));

        dialog.setComponent(panel.withBorder(Borders.singleLine()));
        gui.addWindowAndWait(dialog);
    }
}

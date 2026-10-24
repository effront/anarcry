package gg.effront.anarcry;

import gg.effront.anarcry.tui.AnarCryTui;

public class Main {
    public static void main(String[] args) throws Exception {
        EnvLoader env = null;
        for (int i = 0; i < args.length - 1; i++) {
            if ("--env".equals(args[i])) {
                env = EnvLoader.load(args[i + 1]);
                System.err.println("[env] carregado: target=" + env.target()
                        + " jwt1=" + (env.jwt1().isBlank() ? "(vazio)" : "✓")
                        + " jwt2=" + (env.jwt2().isBlank() ? "(vazio)" : "✓"));
            }
        }
        new AnarCryTui().start(env);
    }
}

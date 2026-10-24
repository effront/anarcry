package gg.effront.anarcry.tui.modes;

import com.googlecode.lanterna.TerminalSize;
import com.googlecode.lanterna.TextColor;
import com.googlecode.lanterna.gui2.BorderLayout;
import com.googlecode.lanterna.gui2.Borders;
import com.googlecode.lanterna.gui2.Button;
import com.googlecode.lanterna.gui2.Component;
import com.googlecode.lanterna.gui2.Direction;
import com.googlecode.lanterna.gui2.EmptySpace;
import com.googlecode.lanterna.gui2.Label;
import com.googlecode.lanterna.gui2.LinearLayout;
import com.googlecode.lanterna.gui2.Panel;
import com.googlecode.lanterna.gui2.TextBox;
import gg.effront.anarcry.tui.PasteableTextBox;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class RepeaterMode {

    public static Component build(String defaultTarget, String jwtToken) {
        var root = new Panel(new BorderLayout());

        // ── REQUEST (left) ──────────────────────────────────────
        var reqPanel = new Panel(new LinearLayout(Direction.VERTICAL));

        Label methodLabel = new Label("  Método + Path:");
        methodLabel.setForegroundColor(TextColor.ANSI.BLUE);
        reqPanel.addComponent(methodLabel);

        var methodBox = new PasteableTextBox(new TerminalSize(30, 1));
        methodBox.setText("GET /");
        reqPanel.addComponent(methodBox);

        reqPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label headersLabel = new Label("  Headers (um por linha):");
        headersLabel.setForegroundColor(TextColor.ANSI.BLUE);
        reqPanel.addComponent(headersLabel);
        var headersBox = new PasteableTextBox(new TerminalSize(30, 4));
        StringBuilder defaultHeaders = new StringBuilder("Host: ").append(hostOf(defaultTarget))
                .append("\nAccept: */*");
        if (jwtToken != null && !jwtToken.isBlank()) {
            defaultHeaders.append("\nAuthorization: Bearer ").append(jwtToken);
        }
        headersBox.setText(defaultHeaders.toString());
        reqPanel.addComponent(headersBox);

        reqPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));
        Label bodyLabel = new Label("  Body (opcional):");
        bodyLabel.setForegroundColor(TextColor.ANSI.BLUE);
        reqPanel.addComponent(bodyLabel);
        var bodyBox = new PasteableTextBox(new TerminalSize(30, 4));
        reqPanel.addComponent(bodyBox);

        reqPanel.addComponent(new EmptySpace(new TerminalSize(1, 1)));

        // ── RESPONSE (right) ────────────────────────────────────
        var respPanel = new Panel(new LinearLayout(Direction.VERTICAL));
        var respBox = new TextBox(new TerminalSize(40, 20), TextBox.Style.MULTI_LINE);
        respBox.setReadOnly(true);
        respBox.setText("Pressione Enviar para executar o request.");
        respPanel.addComponent(respBox, LinearLayout.createLayoutData(LinearLayout.Alignment.Fill));

        // ── SEND BUTTON ─────────────────────────────────────────
        var btnPanel = new Panel(new LinearLayout(Direction.HORIZONTAL));
        btnPanel.addComponent(new Button("Enviar [Enter]",
                () -> sendRequest(defaultTarget, methodBox, headersBox, bodyBox, respBox)));
        reqPanel.addComponent(btnPanel);

        root.addComponent(reqPanel.withBorder(Borders.singleLine("Request")), BorderLayout.Location.LEFT);
        root.addComponent(respPanel.withBorder(Borders.singleLine("Response")), BorderLayout.Location.CENTER);

        return root;
    }

    private static void sendRequest(String baseTarget, TextBox methodBox, TextBox headersBox, TextBox bodyBox,
            TextBox respBox) {
        String methodLine = methodBox.getText().trim();
        String[] parts = methodLine.split(" ", 2);
        String method = parts.length > 0 ? parts[0].toUpperCase() : "GET";
        String path = parts.length > 1 ? parts[1] : "/";

        String scheme = baseTarget.startsWith("https") ? "https" : "http";
        String host = hostOf(baseTarget);
        String url = scheme + "://" + host + path;

        try {
            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder().uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10));

            for (String h : headersBox.getText().lines().toList()) {
                int colon = h.indexOf(':');
                if (colon > 0) {
                    String name = h.substring(0, colon).trim();
                    String val = h.substring(colon + 1).trim();
                    if (!name.equalsIgnoreCase("Host")) {
                        reqBuilder.header(name, val);
                    }
                }
            }

            String body = bodyBox.getText().trim();
            if (!body.isBlank() && !method.equals("GET") && !method.equals("HEAD")) {
                reqBuilder.method(method, HttpRequest.BodyPublishers.ofString(body));
            } else {
                reqBuilder.method(method, HttpRequest.BodyPublishers.noBody());
            }

            HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(5)).build();

            HttpResponse<String> resp = client.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());

            StringBuilder sb = new StringBuilder();
            sb.append("HTTP/1.1 ").append(resp.statusCode()).append("\n");
            resp.headers().map()
                    .forEach((k, vals) -> vals.forEach(v -> sb.append(k).append(": ").append(v).append("\n")));
            sb.append("\n");
            sb.append(resp.body());
            respBox.setText(sb.toString());

        } catch (Exception ex) {
            respBox.setText("[!] Erro: " + ex.getMessage());
        }
    }

    private static String hostOf(String target) {
        try {
            return URI.create(target).getHost();
        } catch (Exception e) {
            return target;
        }
    }
}

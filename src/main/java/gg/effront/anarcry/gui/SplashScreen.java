package gg.effront.anarcry.gui;

import gg.effront.anarcry.Version;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JWindow;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

public final class SplashScreen {

    private static final int WIDTH = 480;
    private static final int HEIGHT = 520;

    private JWindow window;

    public void show() {
        SwingUtilities.invokeLater(this::buildAndShow);
    }

    public void dismiss() {
        SwingUtilities.invokeLater(() -> {
            if (window != null) {
                window.dispose();
                window = null;
            }
        });
    }

    private void buildAndShow() {
        window = new JWindow();

        JPanel content = new JPanel(new BorderLayout(0, 0)) {

            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(0x12, 0x12, 0x1A));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 16, 16);
                g2.dispose();
            }
        };
        content.setOpaque(false);
        content.setBorder(
                BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(new Color(0x3A, 0x3A, 0x4A), 1),
                        BorderFactory.createEmptyBorder(24, 24, 20, 24)));

        java.net.URL logoUrl = getClass().getResource("/icons/splash-logo.png");
        if (logoUrl != null) {
            JLabel logo = new JLabel(new ImageIcon(logoUrl));
            logo.setHorizontalAlignment(SwingConstants.CENTER);
            content.add(logo, BorderLayout.CENTER);
        }

        JPanel bottom = new JPanel(new BorderLayout(0, 4));
        bottom.setOpaque(false);

        JLabel version = new JLabel("v" + Version.get(), SwingConstants.CENTER);
        version.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
        version.setForeground(new Color(0x88, 0x88, 0x99));
        bottom.add(version, BorderLayout.NORTH);

        JLabel loading = new JLabel("Loading...", SwingConstants.CENTER);
        loading.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        loading.setForeground(new Color(0x58, 0xA6, 0xFF));
        bottom.add(loading, BorderLayout.SOUTH);

        content.add(bottom, BorderLayout.SOUTH);

        window.setContentPane(content);
        window.setSize(new Dimension(WIDTH, HEIGHT));
        window.setLocationRelativeTo(null);
        window.setBackground(new Color(0, 0, 0, 0));
        window.setVisible(true);
    }
}

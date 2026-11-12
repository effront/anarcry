package gg.effront.anarcry.gui.views;

import gg.effront.anarcry.model.Finding;
import gg.effront.anarcry.model.Severity;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PiePlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.category.StandardBarPainter;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;

/**
 * Dashboard view with severity stat cards and JFreeChart visualizations.
 */
public class DashboardView extends JPanel {

    private static Color dashBg() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.isDark()
                ? new Color(0x1E, 0x1E, 0x2E)
                : new Color(0xF0, 0xF0, 0xF0);
    }

    private static Color dashFg() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.fg();
    }

    private static Color dashGrid() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.isDark()
                ? new Color(0x44, 0x44, 0x55)
                : new Color(0xC8, 0xC8, 0xC8);
    }

    private static Color dashBorder() {
        return gg.effront.anarcry.gui.theme.AnarCryLaf.isDark()
                ? new Color(0x44, 0x44, 0x55)
                : new Color(0xC0, 0xC0, 0xC0);
    }

    private static final Color COLOR_CRITICAL = new Color(0xF8, 0x51, 0x49);
    private static final Color COLOR_HIGH = new Color(0xD2, 0x99, 0x22);
    private static final Color COLOR_MEDIUM = new Color(0xE3, 0xB3, 0x41);
    private static final Color COLOR_LOW = new Color(0x58, 0xA6, 0xFF);
    private static final Color COLOR_INFO = new Color(0x8B, 0x94, 0x9E);
    private static final Color COLOR_BAR = new Color(0x58, 0xA6, 0xFF);

    private final JLabel criticalCount;
    private final JLabel highCount;
    private final JLabel mediumCount;
    private final JLabel lowCount;
    private final JLabel infoCount;
    private final JLabel summaryLabel;

    @SuppressWarnings("rawtypes")
    private final DefaultPieDataset pieDataset;
    private final DefaultCategoryDataset barDataset;
    private final JFreeChart pieChart;
    private final JFreeChart barChart;

    @SuppressWarnings({"unchecked", "rawtypes"})
    public DashboardView() {
        super(new BorderLayout(0, 8));
        setBackground(dashBg());
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // -- Stat cards --
        criticalCount = statValue("0");
        highCount = statValue("0");
        mediumCount = statValue("0");
        lowCount = statValue("0");
        infoCount = statValue("0");

        JPanel cards = new JPanel(new GridLayout(1, 5, 12, 0));
        cards.setOpaque(false);
        cards.add(statCard("CRITICAL", criticalCount, COLOR_CRITICAL));
        cards.add(statCard("HIGH", highCount, COLOR_HIGH));
        cards.add(statCard("MEDIUM", mediumCount, COLOR_MEDIUM));
        cards.add(statCard("LOW", lowCount, COLOR_LOW));
        cards.add(statCard("INFO", infoCount, COLOR_INFO));
        cards.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));

        // -- Pie chart --
        pieDataset = new DefaultPieDataset();
        pieChart = ChartFactory.createPieChart("Findings by Severity", pieDataset, true, true, false);
        stylePieChart(pieChart);
        ChartPanel piePanel = new ChartPanel(pieChart);
        piePanel.setPreferredSize(new Dimension(400, 300));

        // -- Bar chart --
        barDataset = new DefaultCategoryDataset();
        barChart = ChartFactory.createBarChart("Findings by Module", "Module", "Count", barDataset,
                PlotOrientation.VERTICAL, false, true, false);
        styleBarChart(barChart);
        ChartPanel barPanel = new ChartPanel(barChart);
        barPanel.setPreferredSize(new Dimension(400, 300));

        JSplitPane chartSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, piePanel, barPanel);
        chartSplit.setResizeWeight(0.5);
        chartSplit.setDividerLocation(0.5);
        chartSplit.setOpaque(false);

        summaryLabel = new JLabel("No findings yet.");
        summaryLabel.setForeground(COLOR_INFO);
        summaryLabel.setFont(summaryLabel.getFont().deriveFont(Font.PLAIN, 13f));
        JPanel summaryPanel = new JPanel(new BorderLayout());
        summaryPanel.setBackground(dashBg());
        summaryPanel
                .setBorder(BorderFactory.createCompoundBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, dashBorder()),
                        BorderFactory.createEmptyBorder(8, 4, 4, 4)));
        summaryPanel.add(summaryLabel, BorderLayout.CENTER);

        add(cards, BorderLayout.NORTH);
        add(chartSplit, BorderLayout.CENTER);
        add(summaryPanel, BorderLayout.SOUTH);
    }

    /**
     * Recalculate all stats and charts from the full findings list. Thread-safe.
     */
    public void update(List<Finding> findings) {
        SwingUtilities.invokeLater(() -> rebuild(findings));
    }

    /** Reset all to zero/empty. */
    public void clear() {
        SwingUtilities.invokeLater(() -> rebuild(List.of()));
    }

    @SuppressWarnings("unchecked")
    private void rebuild(List<Finding> findings) {
        Map<Severity, Integer> sevCounts = new EnumMap<>(Severity.class);
        for (Severity s : Severity.values()) {
            sevCounts.put(s, 0);
        }
        Map<String, Integer> moduleCounts = new LinkedHashMap<>();
        for (Finding f : findings) {
            sevCounts.merge(f.severity(), 1, Integer::sum);
            moduleCounts.merge(f.module(), 1, Integer::sum);
        }

        int crit = sevCounts.get(Severity.CRITICAL);
        int high = sevCounts.get(Severity.HIGH);
        int med = sevCounts.get(Severity.MEDIUM);
        int low = sevCounts.get(Severity.LOW);
        int info = sevCounts.get(Severity.INFO);
        int total = findings.size();

        criticalCount.setText(String.valueOf(crit));
        highCount.setText(String.valueOf(high));
        mediumCount.setText(String.valueOf(med));
        lowCount.setText(String.valueOf(low));
        infoCount.setText(String.valueOf(info));

        if (total == 0) {
            summaryLabel.setText("No findings yet.");
        } else {
            StringBuilder topModules = new StringBuilder();
            moduleCounts.entrySet().stream().sorted(Map.Entry.comparingByValue(Comparator.reverseOrder())).limit(5)
                    .forEach(e -> {
                        if (!topModules.isEmpty()) {
                            topModules.append(", ");
                        }
                        topModules.append(e.getKey()).append(" (").append(e.getValue()).append(")");
                    });
            summaryLabel.setText("Total: " + total + " findings -- Top modules: " + topModules);
        }

        pieDataset.clear();
        for (Severity s : Severity.values()) {
            int c = sevCounts.get(s);
            if (c > 0) {
                pieDataset.setValue(s.name(), c);
            }
        }

        barDataset.clear();
        moduleCounts.entrySet().stream().sorted(Map.Entry.comparingByValue(Comparator.reverseOrder()))
                .forEach(e -> barDataset.addValue(e.getValue(), "Findings", e.getKey()));
    }

    // -------------------------------------------------------------------------
    // Styling
    // -------------------------------------------------------------------------

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void stylePieChart(JFreeChart chart) {
        chart.setBackgroundPaint(dashBg());
        chart.getTitle().setPaint(dashFg());
        if (chart.getLegend() != null) {
            chart.getLegend().setBackgroundPaint(dashBg());
            chart.getLegend().setItemPaint(dashFg());
        }
        PiePlot plot = (PiePlot) chart.getPlot();
        plot.setBackgroundPaint(dashBg());
        plot.setOutlineVisible(false);
        plot.setLabelPaint(dashFg());
        plot.setLabelBackgroundPaint(null);
        plot.setLabelOutlinePaint(null);
        plot.setLabelShadowPaint(null);
        plot.setSectionPaint("CRITICAL", COLOR_CRITICAL);
        plot.setSectionPaint("HIGH", COLOR_HIGH);
        plot.setSectionPaint("MEDIUM", COLOR_MEDIUM);
        plot.setSectionPaint("LOW", COLOR_LOW);
        plot.setSectionPaint("INFO", COLOR_INFO);
    }

    private static void styleBarChart(JFreeChart chart) {
        chart.setBackgroundPaint(dashBg());
        chart.getTitle().setPaint(dashFg());
        CategoryPlot plot = chart.getCategoryPlot();
        plot.setBackgroundPaint(dashBg());
        plot.setOutlineVisible(false);
        plot.setRangeGridlinePaint(dashGrid());
        plot.getDomainAxis().setTickLabelPaint(dashFg());
        plot.getDomainAxis().setLabelPaint(dashFg());
        plot.getRangeAxis().setTickLabelPaint(dashFg());
        plot.getRangeAxis().setLabelPaint(dashFg());
        BarRenderer renderer = (BarRenderer) plot.getRenderer();
        renderer.setSeriesPaint(0, COLOR_BAR);
        renderer.setBarPainter(new StandardBarPainter());
        renderer.setShadowVisible(false);
    }

    private static JPanel statCard(String title, JLabel valueLabel, Color accentColor) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(dashBg());
        card.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(accentColor, 2),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setForeground(accentColor);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 11f));
        titleLabel.setAlignmentX(CENTER_ALIGNMENT);

        valueLabel.setAlignmentX(CENTER_ALIGNMENT);
        valueLabel.setForeground(dashFg());

        card.add(titleLabel);
        card.add(Box.createVerticalStrut(4));
        card.add(valueLabel);
        return card;
    }

    private static JLabel statValue(String text) {
        JLabel label = new JLabel(text, SwingConstants.CENTER);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 28f));
        label.setForeground(dashFg());
        return label;
    }
}

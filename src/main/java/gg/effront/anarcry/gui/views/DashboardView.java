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

    private static final Color BG_DARK = new Color(0x1E, 0x1E, 0x2E);
    private static final Color FG_WHITE = Color.WHITE;

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

    @SuppressWarnings("rawtypes")
    private final DefaultPieDataset pieDataset;
    private final DefaultCategoryDataset barDataset;
    private final JFreeChart pieChart;
    private final JFreeChart barChart;

    @SuppressWarnings({"unchecked", "rawtypes"})
    public DashboardView() {
        super(new BorderLayout(0, 8));
        setBackground(BG_DARK);
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // -- Stat cards --
        criticalCount = statValue("0");
        highCount = statValue("0");
        mediumCount = statValue("0");
        lowCount = statValue("0");

        JPanel cards = new JPanel(new GridLayout(1, 4, 12, 0));
        cards.setOpaque(false);
        cards.add(statCard("CRITICAL", criticalCount, COLOR_CRITICAL));
        cards.add(statCard("HIGH", highCount, COLOR_HIGH));
        cards.add(statCard("MEDIUM", mediumCount, COLOR_MEDIUM));
        cards.add(statCard("LOW", lowCount, COLOR_LOW));
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

        add(cards, BorderLayout.NORTH);
        add(chartSplit, BorderLayout.CENTER);
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

        criticalCount.setText(String.valueOf(sevCounts.get(Severity.CRITICAL)));
        highCount.setText(String.valueOf(sevCounts.get(Severity.HIGH)));
        mediumCount.setText(String.valueOf(sevCounts.get(Severity.MEDIUM)));
        lowCount.setText(String.valueOf(sevCounts.get(Severity.LOW)));

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
        chart.setBackgroundPaint(BG_DARK);
        chart.getTitle().setPaint(FG_WHITE);
        if (chart.getLegend() != null) {
            chart.getLegend().setBackgroundPaint(BG_DARK);
            chart.getLegend().setItemPaint(FG_WHITE);
        }
        PiePlot plot = (PiePlot) chart.getPlot();
        plot.setBackgroundPaint(BG_DARK);
        plot.setOutlineVisible(false);
        plot.setLabelPaint(FG_WHITE);
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
        chart.setBackgroundPaint(BG_DARK);
        chart.getTitle().setPaint(FG_WHITE);
        CategoryPlot plot = chart.getCategoryPlot();
        plot.setBackgroundPaint(BG_DARK);
        plot.setOutlineVisible(false);
        plot.setRangeGridlinePaint(new Color(0x44, 0x44, 0x55));
        plot.getDomainAxis().setTickLabelPaint(FG_WHITE);
        plot.getDomainAxis().setLabelPaint(FG_WHITE);
        plot.getRangeAxis().setTickLabelPaint(FG_WHITE);
        plot.getRangeAxis().setLabelPaint(FG_WHITE);
        BarRenderer renderer = (BarRenderer) plot.getRenderer();
        renderer.setSeriesPaint(0, COLOR_BAR);
        renderer.setBarPainter(new StandardBarPainter());
        renderer.setShadowVisible(false);
    }

    private static JPanel statCard(String title, JLabel valueLabel, Color accentColor) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(BG_DARK);
        card.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(accentColor, 2),
                BorderFactory.createEmptyBorder(8, 12, 8, 12)));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setForeground(accentColor);
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 11f));
        titleLabel.setAlignmentX(CENTER_ALIGNMENT);

        valueLabel.setAlignmentX(CENTER_ALIGNMENT);
        valueLabel.setForeground(FG_WHITE);

        card.add(titleLabel);
        card.add(Box.createVerticalStrut(4));
        card.add(valueLabel);
        return card;
    }

    private static JLabel statValue(String text) {
        JLabel label = new JLabel(text, SwingConstants.CENTER);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 28f));
        label.setForeground(FG_WHITE);
        return label;
    }
}

package aib.framework.ui;

import aib.framework.model.AnalysisResult;
import aib.framework.model.HeuristicFinding;
import java.awt.BorderLayout;
import java.awt.Font;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class AnalysisResultsPanel extends JPanel {
    private final JTextArea textArea;

    public AnalysisResultsPanel() {
        super(new BorderLayout());
        textArea = new JTextArea();
        textArea.setEditable(false);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        add(new JScrollPane(textArea), BorderLayout.CENTER);
    }

    public void showResult(AnalysisResult result) {
        StringBuilder builder = new StringBuilder();
        builder.append("Overall risk: ").append(result.getOverallRisk()).append("\n\n");
        builder.append(result.getSummary()).append("\n\n");

        for (HeuristicFinding finding : result.getFindings()) {
            builder.append("[").append(finding.getRiskLevel()).append("] ")
                .append(finding.getFunctionName())
                .append(" @ ").append(finding.getAddress()).append("\n");
            builder.append(finding.getTitle()).append("\n");
            builder.append("Type: ").append(finding.getType()).append("\n");
            builder.append("Explanation: ").append(finding.getExplanation()).append("\n");
            builder.append("Theoretical hypothesis: ").append(finding.getSafeExploitHypothesis()).append("\n");
            builder.append("Fuzzing: ").append(finding.getFuzzingSuggestion()).append("\n");
            builder.append("Mitigation: ").append(finding.getMitigation()).append("\n\n");
        }

        textArea.setText(builder.toString());
        textArea.setCaretPosition(0);
    }
}

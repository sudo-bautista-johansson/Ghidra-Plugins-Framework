package aib.framework.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AnalysisResult {
    private final RiskLevel overallRisk;
    private final List<HeuristicFinding> findings;
    private final String summary;

    public AnalysisResult(RiskLevel overallRisk, List<HeuristicFinding> findings, String summary) {
        this.overallRisk = overallRisk;
        this.findings = new ArrayList<>(findings);
        this.summary = summary;
    }

    public RiskLevel getOverallRisk() {
        return overallRisk;
    }

    public List<HeuristicFinding> getFindings() {
        return Collections.unmodifiableList(findings);
    }

    public String getSummary() {
        return summary;
    }
}

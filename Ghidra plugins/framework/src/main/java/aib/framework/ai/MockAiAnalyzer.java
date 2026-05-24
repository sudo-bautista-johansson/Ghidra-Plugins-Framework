package aib.framework.ai;

import aib.framework.model.AnalysisContext;
import aib.framework.model.AnalysisResult;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class MockAiAnalyzer implements AiAnalyzer {
    @Override
    public AnalysisResult analyze(AnalysisContext context, List<HeuristicFinding> localFindings) {
        List<HeuristicFinding> merged = new ArrayList<>(localFindings);
        RiskLevel overall = RiskLevel.LOW;
        for (HeuristicFinding finding : merged) {
            overall = RiskLevel.max(overall, finding.getRiskLevel());
        }

        String summary = "Offline development mode: the mock analyzer preserved local heuristic findings and assigned an aggregated defensive risk rating.";
        return new AnalysisResult(overall, merged, summary);
    }
}

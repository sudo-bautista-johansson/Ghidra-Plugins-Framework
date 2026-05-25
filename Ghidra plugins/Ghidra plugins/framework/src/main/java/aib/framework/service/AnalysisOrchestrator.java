package aib.framework.service;

import aib.framework.ai.AiAnalyzer;
import aib.framework.extract.BinaryContextExtractor;
import aib.framework.heuristic.HeuristicEngine;
import aib.framework.model.AnalysisContext;
import aib.framework.model.AnalysisResult;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import ghidra.program.model.listing.Function;
import java.util.ArrayList;
import java.util.List;

public class AnalysisOrchestrator {
    private final BinaryContextExtractor extractor;
    private final HeuristicEngine heuristicEngine;
    private final AiAnalyzer aiAnalyzer;

    public AnalysisOrchestrator(
            BinaryContextExtractor extractor,
            HeuristicEngine heuristicEngine,
            AiAnalyzer aiAnalyzer) {
        this.extractor = extractor;
        this.heuristicEngine = heuristicEngine;
        this.aiAnalyzer = aiAnalyzer;
    }

    public AnalysisResult analyze(Function selectedFunction) throws Exception {
        AnalysisContext context = extractor.extractCurrentSelectionOrAllFunctions(selectedFunction);
        List<HeuristicFinding> localFindings = heuristicEngine.evaluate(context);
        AnalysisResult aiResult = aiAnalyzer.analyze(context, localFindings);
        return merge(localFindings, aiResult, context);
    }

    private AnalysisResult merge(
            List<HeuristicFinding> localFindings,
            AnalysisResult aiResult,
            AnalysisContext context) {
        List<HeuristicFinding> findings = new ArrayList<>(localFindings);
        for (HeuristicFinding finding : aiResult.getFindings()) {
            if (!findings.contains(finding)) {
                findings.add(finding);
            }
        }

        RiskLevel overall = aiResult.getOverallRisk();
        for (HeuristicFinding finding : findings) {
            overall = RiskLevel.max(overall, finding.getRiskLevel());
        }

        String summary = aiResult.getSummary() + " Functions analyzed: " + context.getFunctions().size() + ".";
        return new AnalysisResult(overall, findings, summary);
    }
}

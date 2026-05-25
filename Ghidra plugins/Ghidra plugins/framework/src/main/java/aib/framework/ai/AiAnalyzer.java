package aib.framework.ai;

import aib.framework.model.AnalysisContext;
import aib.framework.model.AnalysisResult;
import aib.framework.model.HeuristicFinding;
import java.util.List;

public interface AiAnalyzer {
    AnalysisResult analyze(AnalysisContext context, List<HeuristicFinding> localFindings) throws Exception;
}

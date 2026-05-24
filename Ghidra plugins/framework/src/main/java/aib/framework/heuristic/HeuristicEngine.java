package aib.framework.heuristic;

import aib.framework.model.AnalysisContext;
import aib.framework.model.HeuristicFinding;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class HeuristicEngine {
    private final List<HeuristicRule> rules;

    public HeuristicEngine() {
        this(Arrays.asList(
            new DangerousCallRule(),
            new MemorySafetyRule(),
            new ParserAbuseRule(),
            new AuthLogicRule(),
            new WeakCryptoRule(),
            new FuzzingSurfaceRule(),
            new SuspiciousStringRule(),
            new PseudocodePatternRule()
        ));
    }

    public HeuristicEngine(List<HeuristicRule> rules) {
        this.rules = new ArrayList<>(rules);
    }

    public List<HeuristicFinding> evaluate(AnalysisContext context) {
        List<HeuristicFinding> findings = new ArrayList<>();
        for (aib.framework.model.FunctionContext functionContext : context.getFunctions()) {
            for (HeuristicRule rule : rules) {
                findings.addAll(rule.evaluate(functionContext));
            }
        }
        return findings;
    }
}

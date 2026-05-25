package aib.framework.heuristic;

import aib.framework.model.FindingType;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class PseudocodePatternRule implements HeuristicRule {
    @Override
    public List<HeuristicFinding> evaluate(FunctionContext functionContext) {
        List<HeuristicFinding> findings = new ArrayList<>();
        String pseudocode = functionContext.getPseudocode();
        if (pseudocode == null || pseudocode.isEmpty()) {
            return findings;
        }

        String lowered = pseudocode.toLowerCase();
        if (lowered.contains("malloc(") && lowered.contains("memcpy(") && !lowered.contains("sizeof")) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.MEMORY_PATTERN,
                RiskLevel.HIGH,
                "Allocation and copy path deserves review",
                "The pseudocode shows dynamic allocation followed by a copy operation without an obvious nearby size guard.",
                "If the copied length is influenced by external state, heap overwrite or over-read conditions may be theoretically possible.",
                "Vary allocation size metadata, length fields, and object counts that reach this path.",
                "Trace the exact source of the copy length and enforce strict upper bounds before allocation and copy."
            ));
        }

        if (lowered.contains("switch") && lowered.contains("default:") && lowered.contains("return 0")) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.CONTROL_FLOW_PATTERN,
                RiskLevel.LOW,
                "Potentially permissive default branch",
                "The control flow suggests a default path that may silently accept or ignore unsupported states.",
                "If security-relevant selectors are accepted by default, invalid states could bypass intended validation.",
                "Mutate selector fields and unsupported enum values during fuzzing to observe fallback behavior.",
                "Make default branches explicit, logged, and fail-closed when the selector is security-relevant."
            ));
        }

        return findings;
    }
}

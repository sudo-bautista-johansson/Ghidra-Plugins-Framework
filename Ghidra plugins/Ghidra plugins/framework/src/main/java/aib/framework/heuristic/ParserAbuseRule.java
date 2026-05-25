package aib.framework.heuristic;

import aib.framework.model.FindingType;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class ParserAbuseRule implements HeuristicRule {
    @Override
    public List<HeuristicFinding> evaluate(FunctionContext functionContext) {
        List<HeuristicFinding> findings = new ArrayList<>();

        boolean parserShape = HeuristicSupport.callsAny(functionContext, "read", "recv", "fread", "scanf", "sscanf")
            || HeuristicSupport.pseudocodeContains(functionContext, "parse", "header", "length", "offset", "magic");

        if (parserShape && functionContext.getBasicBlockCount() > 12) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.DATA_FLOW_PATTERN,
                RiskLevel.MEDIUM,
                "Complex parser-like control flow",
                "The function looks like a parser or decoder with enough branching to justify careful boundary and state-machine review.",
                "If inconsistent field validation exists across branches, malformed inputs could theoretically reach unsafe states or memory misuse.",
                "Generate inputs with truncated headers, overlapping offsets, recursive containers, and contradictory declared lengths.",
                "Centralize field validation, normalize bounds handling, and reject malformed state transitions early."
            ));
        }

        if (HeuristicSupport.pseudocodeContains(functionContext, "switch", "case")
                && HeuristicSupport.pseudocodeContains(functionContext, "default:")
                && HeuristicSupport.pseudocodeContains(functionContext, "break;")) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.CONTROL_FLOW_PATTERN,
                RiskLevel.LOW,
                "Parser dispatch table worth fail-closed review",
                "The function appears to dispatch on message or record types and may require a fail-closed default path.",
                "If unsupported record types continue execution instead of terminating cleanly, hidden parsing states may be reachable.",
                "Try unsupported type identifiers, duplicate sections, zero-length records, and reordered fields.",
                "Ensure unknown selectors terminate parsing safely and log rejected states for review."
            ));
        }

        return findings;
    }
}

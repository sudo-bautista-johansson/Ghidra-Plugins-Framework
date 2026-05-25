package aib.framework.heuristic;

import aib.framework.model.FindingType;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class DangerousCallRule implements HeuristicRule {
    private static final Set<String> DANGEROUS_CALLS = new HashSet<>(Arrays.asList(
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy", "recv", "read", "scanf"
    ));

    @Override
    public List<HeuristicFinding> evaluate(FunctionContext functionContext) {
        List<HeuristicFinding> findings = new ArrayList<>();
        for (String callee : functionContext.getCalledFunctions()) {
            String normalized = callee.toLowerCase();
            if (!DANGEROUS_CALLS.contains(normalized)) {
                continue;
            }

            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.DANGEROUS_CALL,
                riskForCall(normalized),
                "Potentially unsafe call: " + callee,
                "The function invokes a historically risky API that often appears in overflow or truncation bugs when size validation is incomplete.",
                "If attacker-controlled input reaches this call without validated bounds, memory corruption or state corruption may become theoretically reachable.",
                "Prioritize corpus inputs that vary length, terminators, encoding, and structure around the arguments flowing into " + callee + ".",
                "Validate source length, destination capacity, and signedness assumptions before the call. Prefer bounded APIs and explicit length checks."
            ));
        }
        return findings;
    }

    private RiskLevel riskForCall(String call) {
        if ("gets".equals(call) || "strcpy".equals(call) || "vsprintf".equals(call)) {
            return RiskLevel.HIGH;
        }
        if ("memcpy".equals(call) || "recv".equals(call) || "read".equals(call)) {
            return RiskLevel.MEDIUM;
        }
        return RiskLevel.MEDIUM;
    }
}

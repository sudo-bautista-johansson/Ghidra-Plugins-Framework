package aib.framework.heuristic;

import aib.framework.model.FindingType;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class AuthLogicRule implements HeuristicRule {
    @Override
    public List<HeuristicFinding> evaluate(FunctionContext functionContext) {
        List<HeuristicFinding> findings = new ArrayList<>();

        boolean authContext = HeuristicSupport.stringsContain(functionContext, "auth", "login", "token", "password", "session", "role")
            || HeuristicSupport.pseudocodeContains(functionContext, "auth", "token", "password", "permission", "session");

        if (!authContext) {
            return findings;
        }

        if (HeuristicSupport.pseudocodeContains(functionContext, "strcmp(", "strncmp(")
                || HeuristicSupport.callsAny(functionContext, "strcmp", "strncmp")) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.AI_HEURISTIC,
                RiskLevel.MEDIUM,
                "Authentication comparison path",
                "The function appears to perform string-based authentication or authorization checks that deserve review for bypass, canonicalization, and timing issues.",
                "If credentials, roles, or tokens are compared in inconsistent normalized forms, a theoretical bypass or privilege confusion bug may emerge.",
                "Fuzz token casing, Unicode normalization, prefix collisions, null-byte truncation, and whitespace handling.",
                "Normalize identity material before comparison, apply constant-time comparison where appropriate, and fail closed on parse ambiguity."
            ));
        }

        if (HeuristicSupport.pseudocodeContains(functionContext, "return 1;", "return true;")
                && HeuristicSupport.pseudocodeContains(functionContext, "if (")
                && functionContext.getBasicBlockCount() <= 4) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.CONTROL_FLOW_PATTERN,
                RiskLevel.LOW,
                "Small auth gate merits manual review",
                "A compact authorization function can hide permissive early returns or inverted checks that are easy to miss in decompiled output.",
                "If any exceptional path defaults to success, invalid or partially parsed identities may be accepted.",
                "Exercise malformed, empty, and partially valid credential objects and verify all failure paths deny access.",
                "Invert the design toward explicit deny-by-default outcomes and isolate success conditions."
            ));
        }

        return findings;
    }
}

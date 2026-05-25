package aib.framework.heuristic;

import aib.framework.model.FindingType;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class SuspiciousStringRule implements HeuristicRule {
    @Override
    public List<HeuristicFinding> evaluate(FunctionContext functionContext) {
        List<HeuristicFinding> findings = new ArrayList<>();
        for (String value : functionContext.getSuspiciousStrings()) {
            String normalized = value.toLowerCase();
            if (!looksSensitive(normalized)) {
                continue;
            }

            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.SUSPICIOUS_STRING,
                RiskLevel.MEDIUM,
                "Suspicious embedded string",
                "The function is near a string that suggests authentication, token handling, process execution, or command dispatch logic.",
                "If the string participates in parser, dispatcher, or auth logic, malformed inputs could expose trust-boundary mistakes or hidden execution paths.",
                "Exercise parsers and handlers associated with this string using malformed tokens, boundary lengths, and invalid state transitions.",
                "Review trust boundaries, parser error handling, and command authorization around the referenced string."
            ));
        }
        return findings;
    }

    private boolean looksSensitive(String normalized) {
        return normalized.contains("token")
            || normalized.contains("auth")
            || normalized.contains("password")
            || normalized.contains("cmd")
            || normalized.contains("/bin/sh")
            || normalized.contains("powershell");
    }
}

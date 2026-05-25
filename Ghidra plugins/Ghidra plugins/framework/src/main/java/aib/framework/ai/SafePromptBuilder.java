package aib.framework.ai;

import aib.framework.model.AnalysisContext;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import java.util.List;

public class SafePromptBuilder {
    public String build(AnalysisContext context, List<HeuristicFinding> localFindings) {
        StringBuilder builder = new StringBuilder();
        builder.append("You are a defensive binary-analysis assistant.\n");
        builder.append("Do not generate exploits, payloads, or compromise instructions.\n");
        builder.append("Return only: vulnerabilities, suspicious patterns, risk rating, explanation, safe theoretical hypothesis, fuzzing ideas, mitigations.\n\n");
        builder.append("Program: ").append(context.getProgramName()).append("\n");
        builder.append("Format: ").append(context.getExecutableFormat()).append("\n");
        builder.append("Language: ").append(context.getLanguageId()).append("\n\n");

        for (FunctionContext functionContext : context.getFunctions()) {
            builder.append("Function: ").append(functionContext.getFunctionName())
                .append(" @ ").append(functionContext.getEntryPoint()).append("\n");
            builder.append("Signature: ").append(functionContext.getSignature()).append("\n");
            builder.append("Calls: ").append(functionContext.getCalledFunctions()).append("\n");
            builder.append("Strings: ").append(functionContext.getSuspiciousStrings()).append("\n");
            builder.append("Pseudocode:\n").append(functionContext.getPseudocode()).append("\n\n");
        }

        builder.append("Local heuristic findings:\n");
        for (HeuristicFinding finding : localFindings) {
            builder.append("- [").append(finding.getRiskLevel()).append("] ")
                .append(finding.getFunctionName()).append(": ")
                .append(finding.getTitle()).append("\n");
        }
        return builder.toString();
    }
}

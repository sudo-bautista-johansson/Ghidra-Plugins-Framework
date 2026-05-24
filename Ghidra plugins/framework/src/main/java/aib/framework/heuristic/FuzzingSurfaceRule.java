package aib.framework.heuristic;

import aib.framework.model.FindingType;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class FuzzingSurfaceRule implements HeuristicRule {
    @Override
    public List<HeuristicFinding> evaluate(FunctionContext functionContext) {
        List<HeuristicFinding> findings = new ArrayList<>();

        boolean inputFacing = HeuristicSupport.callsAny(functionContext, "recv", "read", "fread", "accept", "socket")
            || HeuristicSupport.stringsContain(functionContext, "http", "json", "xml", "protobuf", "packet", "request")
            || HeuristicSupport.pseudocodeContains(functionContext, "length", "header", "opcode", "request", "response");

        if (inputFacing && functionContext.getInstructionCount() > 40) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.REVIEW_NOTE,
                RiskLevel.MEDIUM,
                "High-value fuzzing surface",
                "The function appears to sit on an externally influenced input path and has enough complexity to justify targeted fuzzing.",
                "If state, size, encoding, and dispatch validations diverge, theoretical parser crashes or trust-boundary failures may be exposed.",
                "Start with structure-aware mutations for size fields, nested records, duplicated tags, unsupported opcodes, and partial truncation.",
                "Add harness coverage around input normalization, parse stages, and all reject paths to reduce silent parser drift."
            ));
        }

        return findings;
    }
}

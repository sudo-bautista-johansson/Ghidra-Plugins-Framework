package aib.framework.heuristic;

import aib.framework.model.FindingType;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class MemorySafetyRule implements HeuristicRule {
    @Override
    public List<HeuristicFinding> evaluate(FunctionContext functionContext) {
        List<HeuristicFinding> findings = new ArrayList<>();

        if (HeuristicSupport.callsAny(functionContext, "malloc", "calloc", "realloc")
                && HeuristicSupport.callsAny(functionContext, "memcpy", "memmove", "strcpy", "strncpy")) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.MEMORY_PATTERN,
                RiskLevel.HIGH,
                "Heap allocation followed by copy operations",
                "The function combines dynamic allocation with memory-copy behavior, which is a common source of size-calculation and lifetime bugs.",
                "If input-controlled length or count values influence allocation and subsequent writes, a theoretical heap corruption path may exist.",
                "Mutate length fields, element counts, and structure nesting that reach allocation and copy boundaries.",
                "Trace allocator size math, validate integer ranges, and ensure the copied byte count cannot exceed the allocated region."
            ));
        }

        if (HeuristicSupport.pseudocodeContains(functionContext, "memcpy(", "memmove(")
                && !HeuristicSupport.pseudocodeContains(functionContext, "sizeof(", "min(", "if (")) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.MEMORY_PATTERN,
                RiskLevel.MEDIUM,
                "Copy operation without obvious nearby guard",
                "The pseudocode shows a raw copy primitive without an immediately visible bound or truncation check.",
                "If the copy length derives from untrusted metadata, the function may become a candidate for over-read or overwrite review.",
                "Focus fuzzing on malformed size headers, negative-to-large signed conversions, and desynchronization between declared and actual lengths.",
                "Introduce explicit bounds checks adjacent to the copy primitive and validate all size transformations before use."
            ));
        }

        return findings;
    }
}

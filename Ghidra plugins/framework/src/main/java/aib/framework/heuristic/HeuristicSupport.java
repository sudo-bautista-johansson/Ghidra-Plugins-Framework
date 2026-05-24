package aib.framework.heuristic;

import aib.framework.model.FunctionContext;
import java.util.List;

final class HeuristicSupport {
    private HeuristicSupport() {
    }

    static boolean callsAny(FunctionContext functionContext, String... names) {
        List<String> calls = functionContext.getCalledFunctions();
        for (String call : calls) {
            String normalizedCall = call.toLowerCase();
            for (String name : names) {
                if (normalizedCall.equals(name.toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean pseudocodeContains(FunctionContext functionContext, String... tokens) {
        String pseudocode = functionContext.getPseudocode();
        if (pseudocode == null || pseudocode.isEmpty()) {
            return false;
        }
        String lowered = pseudocode.toLowerCase();
        for (String token : tokens) {
            if (lowered.contains(token.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    static boolean stringsContain(FunctionContext functionContext, String... tokens) {
        for (String value : functionContext.getSuspiciousStrings()) {
            String lowered = value.toLowerCase();
            for (String token : tokens) {
                if (lowered.contains(token.toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }
}

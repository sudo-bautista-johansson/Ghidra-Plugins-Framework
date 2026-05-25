package aib.framework.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FunctionContext {
    private final String functionName;
    private final String entryPoint;
    private final String signature;
    private final String pseudocode;
    private final List<String> calledFunctions;
    private final List<String> suspiciousStrings;
    private final int basicBlockCount;
    private final int instructionCount;

    public FunctionContext(
            String functionName,
            String entryPoint,
            String signature,
            String pseudocode,
            List<String> calledFunctions,
            List<String> suspiciousStrings,
            int basicBlockCount,
            int instructionCount) {
        this.functionName = functionName;
        this.entryPoint = entryPoint;
        this.signature = signature;
        this.pseudocode = pseudocode;
        this.calledFunctions = new ArrayList<>(calledFunctions);
        this.suspiciousStrings = new ArrayList<>(suspiciousStrings);
        this.basicBlockCount = basicBlockCount;
        this.instructionCount = instructionCount;
    }

    public String getFunctionName() {
        return functionName;
    }

    public String getEntryPoint() {
        return entryPoint;
    }

    public String getSignature() {
        return signature;
    }

    public String getPseudocode() {
        return pseudocode;
    }

    public List<String> getCalledFunctions() {
        return Collections.unmodifiableList(calledFunctions);
    }

    public List<String> getSuspiciousStrings() {
        return Collections.unmodifiableList(suspiciousStrings);
    }

    public int getBasicBlockCount() {
        return basicBlockCount;
    }

    public int getInstructionCount() {
        return instructionCount;
    }
}

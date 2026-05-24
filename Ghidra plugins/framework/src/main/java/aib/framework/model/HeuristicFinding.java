package aib.framework.model;

public class HeuristicFinding {
    private final String functionName;
    private final String address;
    private final FindingType type;
    private final RiskLevel riskLevel;
    private final String title;
    private final String explanation;
    private final String safeExploitHypothesis;
    private final String fuzzingSuggestion;
    private final String mitigation;

    public HeuristicFinding(
            String functionName,
            String address,
            FindingType type,
            RiskLevel riskLevel,
            String title,
            String explanation,
            String safeExploitHypothesis,
            String fuzzingSuggestion,
            String mitigation) {
        this.functionName = functionName;
        this.address = address;
        this.type = type;
        this.riskLevel = riskLevel;
        this.title = title;
        this.explanation = explanation;
        this.safeExploitHypothesis = safeExploitHypothesis;
        this.fuzzingSuggestion = fuzzingSuggestion;
        this.mitigation = mitigation;
    }

    public String getFunctionName() {
        return functionName;
    }

    public String getAddress() {
        return address;
    }

    public FindingType getType() {
        return type;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public String getTitle() {
        return title;
    }

    public String getExplanation() {
        return explanation;
    }

    public String getSafeExploitHypothesis() {
        return safeExploitHypothesis;
    }

    public String getFuzzingSuggestion() {
        return fuzzingSuggestion;
    }

    public String getMitigation() {
        return mitigation;
    }
}

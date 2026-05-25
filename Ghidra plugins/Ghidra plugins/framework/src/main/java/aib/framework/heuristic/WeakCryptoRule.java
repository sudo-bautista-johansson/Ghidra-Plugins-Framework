package aib.framework.heuristic;

import aib.framework.model.FindingType;
import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import aib.framework.model.RiskLevel;
import java.util.ArrayList;
import java.util.List;

public class WeakCryptoRule implements HeuristicRule {
    @Override
    public List<HeuristicFinding> evaluate(FunctionContext functionContext) {
        List<HeuristicFinding> findings = new ArrayList<>();

        if (HeuristicSupport.callsAny(functionContext, "md5", "sha1", "rc4", "des", "rand", "srand")
                || HeuristicSupport.stringsContain(functionContext, "md5", "sha1", "rc4", "des", "seed")) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.REVIEW_NOTE,
                RiskLevel.MEDIUM,
                "Potential weak cryptography or weak randomness",
                "The function references cryptographic or pseudo-random primitives that are often unsuitable for modern security-sensitive designs.",
                "If these primitives protect credentials, sessions, integrity decisions, or secrets, theoretical downgrade or predictability issues may be present.",
                "Target key derivation inputs, nonce reuse scenarios, predictable seeds, and malformed encrypted records that stress error handling.",
                "Prefer modern vetted primitives, cryptographically secure randomness, and explicit algorithm migration paths."
            ));
        }

        if (HeuristicSupport.pseudocodeContains(functionContext, "xor", "^")
                && HeuristicSupport.pseudocodeContains(functionContext, "for", "while")) {
            findings.add(new HeuristicFinding(
                functionContext.getFunctionName(),
                functionContext.getEntryPoint(),
                FindingType.REVIEW_NOTE,
                RiskLevel.LOW,
                "Custom obfuscation or home-grown crypto pattern",
                "The pseudocode suggests iterative XOR-based transformation logic, which often indicates custom obfuscation or non-standard protection.",
                "If used for integrity or confidentiality, theoretical recovery or tampering weaknesses may exist due to low cryptographic robustness.",
                "Probe edge cases around key length, empty buffers, repeated blocks, and malformed encoded payloads.",
                "Replace ad hoc transformations with standard authenticated cryptographic constructions."
            ));
        }

        return findings;
    }
}

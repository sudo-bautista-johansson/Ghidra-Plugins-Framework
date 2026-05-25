package aib.framework.heuristic;

import aib.framework.model.FunctionContext;
import aib.framework.model.HeuristicFinding;
import java.util.List;

public interface HeuristicRule {
    List<HeuristicFinding> evaluate(FunctionContext functionContext);
}

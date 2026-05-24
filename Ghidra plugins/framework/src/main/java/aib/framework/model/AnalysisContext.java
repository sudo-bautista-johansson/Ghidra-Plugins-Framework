package aib.framework.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class AnalysisContext {
    private final String programName;
    private final String executableFormat;
    private final String languageId;
    private final List<FunctionContext> functions;

    public AnalysisContext(
            String programName,
            String executableFormat,
            String languageId,
            List<FunctionContext> functions) {
        this.programName = programName;
        this.executableFormat = executableFormat;
        this.languageId = languageId;
        this.functions = new ArrayList<>(functions);
    }

    public String getProgramName() {
        return programName;
    }

    public String getExecutableFormat() {
        return executableFormat;
    }

    public String getLanguageId() {
        return languageId;
    }

    public List<FunctionContext> getFunctions() {
        return Collections.unmodifiableList(functions);
    }
}

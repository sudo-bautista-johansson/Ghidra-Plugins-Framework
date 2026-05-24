package aib.framework.extract;

import aib.framework.model.AnalysisContext;
import aib.framework.model.FunctionContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReferenceManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class BinaryContextExtractor {
    private final Program program;
    private final TaskMonitor monitor;

    public BinaryContextExtractor(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    public AnalysisContext extractCurrentSelectionOrAllFunctions(Function selectedFunction) throws Exception {
        List<FunctionContext> functions = new ArrayList<>();
        if (selectedFunction != null) {
            functions.add(extractFunction(selectedFunction));
        }
        else {
            FunctionIterator iterator = program.getListing().getFunctions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                functions.add(extractFunction(iterator.next()));
            }
        }

        return new AnalysisContext(
            program.getName(),
            program.getExecutableFormat(),
            program.getLanguageID().getIdAsString(),
            functions
        );
    }

    public FunctionContext extractFunction(Function function) throws Exception {
        return new FunctionContext(
            function.getName(),
            function.getEntryPoint().toString(),
            function.getSignature().toString(),
            decompile(function),
            collectCalledFunctions(function),
            collectInterestingStrings(function),
            countBlocks(function),
            countInstructions(function)
        );
    }

    private String decompile(Function function) {
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(function, 30, monitor);
            if (results != null && results.decompileCompleted() && results.getDecompiledFunction() != null) {
                return results.getDecompiledFunction().getC();
            }
        }
        catch (Exception ignored) {
        }
        finally {
            decompiler.dispose();
        }
        return "";
    }

    private List<String> collectCalledFunctions(Function function) {
        Set<String> calls = new HashSet<>();
        InstructionIterator iterator = program.getListing().getInstructions(function.getBody(), true);
        ReferenceManager referenceManager = program.getReferenceManager();
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            Reference[] references = referenceManager.getReferencesFrom(instruction.getAddress());
            for (Reference reference : references) {
                Function callee = program.getListing().getFunctionAt(reference.getToAddress());
                if (callee != null) {
                    calls.add(callee.getName());
                }
            }
        }
        return new ArrayList<>(calls);
    }

    private List<String> collectInterestingStrings(Function function) throws MemoryAccessException {
        Set<String> values = new HashSet<>();
        InstructionIterator iterator = program.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            int operandCount = instruction.getNumOperands();
            for (int index = 0; index < operandCount; index++) {
                for (Object object : instruction.getOpObjects(index)) {
                    if (!(object instanceof ghidra.program.model.address.Address)) {
                        continue;
                    }

                    ghidra.program.model.address.Address address = (ghidra.program.model.address.Address) object;
                    String candidate = readAscii(address, 64);
                    if (candidate.length() >= 4) {
                        values.add(candidate);
                    }
                }
            }
        }
        return new ArrayList<>(values);
    }

    private String readAscii(ghidra.program.model.address.Address address, int maxLen) throws MemoryAccessException {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < maxLen; i++) {
            byte value;
            try {
                value = program.getMemory().getByte(address.add(i));
            }
            catch (Exception exception) {
                break;
            }
            if (value == 0) {
                break;
            }
            if (value < 0x20 || value > 0x7e) {
                return "";
            }
            builder.append((char) value);
        }
        return builder.toString();
    }

    private int countBlocks(Function function) throws CancelledException {
        BasicBlockModel model = new BasicBlockModel(program);
        AddressSetView body = function.getBody();
        CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
        int count = 0;
        while (blocks.hasNext()) {
            CodeBlock ignored = blocks.next();
            count++;
        }
        return count;
    }

    private int countInstructions(Function function) {
        int count = 0;
        InstructionIterator iterator = program.getListing().getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            iterator.next();
            count++;
        }
        return count;
    }
}

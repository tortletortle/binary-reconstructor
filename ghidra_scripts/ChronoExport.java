// Export raw decompiler text for exactly one named function. No execution.
// @category ChronoCompiler
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ChronoExport extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("function output-directory timeout-seconds");
        Function found = null;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            if (f.getName().equals(args[0])) {
                if (found != null) throw new IllegalArgumentException("ambiguous function");
                found = f;
            }
        }
        if (found == null || found.isExternal() || found.isThunk())
            throw new IllegalArgumentException("missing or external/thunk function");
        Path out = Path.of(args[1]);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("openProgram failed");
            DecompileResults r = decompiler.decompileFunction(found, Integer.parseInt(args[2]), monitor);
            if (!r.decompileCompleted() || r.getDecompiledFunction() == null)
                throw new IllegalStateException("decompiler failed: " + r.getErrorMessage());
            Files.writeString(out.resolve("decompiled.c"), r.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
            Files.writeString(out.resolve("entry.txt"), found.getEntryPoint().toString(), StandardCharsets.UTF_8);
        } finally { decompiler.dispose(); }
    }
}

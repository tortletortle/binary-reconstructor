// Export decompiler C, HighFunction P-code, and basic-block CFG metadata.
// Raw output is data only; ChronoCompiler never executes this text.
// @category ChronoCompiler
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;

public class ChronoExport extends GhidraScript {
    private static String q(String value) {
        if (value == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int)c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    private void appendVarnode(StringBuilder b, Varnode vn) {
        if (vn == null) { b.append("null"); return; }
        String space = vn.getAddress().getAddressSpace().getName();
        String kind = vn.isConstant() ? "constant" : vn.isRegister() ? "register" :
                      vn.isUnique() ? "unique" : vn.isAddress() ? "memory" : "other";
        String highName = null;
        String highType = null;
        String registerName = null;
        if (vn.isRegister()) {
            Register register = currentProgram.getLanguage().getRegister(vn.getAddress(), vn.getSize());
            if (register != null) registerName = register.getName();
        }
        if (vn instanceof VarnodeAST) {
            HighVariable high = ((VarnodeAST)vn).getHigh();
            if (high != null) {
                highName = high.getName();
                if (high.getDataType() != null) highType = high.getDataType().getName();
            }
        }
        b.append("{\"kind\":").append(q(kind));
        b.append(",\"space\":").append(q(space));
        b.append(",\"offset_hex\":").append(q(hex(vn.getOffset())));
        b.append(",\"size\":").append(vn.getSize());
        b.append(",\"address\":").append(q(vn.getAddress().toString()));
        b.append(",\"register_name\":").append(q(registerName));
        b.append(",\"high_name\":").append(q(highName));
        b.append(",\"high_type\":").append(q(highType));
        if (vn instanceof VarnodeAST) {
            VarnodeAST ast = (VarnodeAST)vn;
            b.append(",\"varnode_id\":").append(ast.getUniqueId());
            b.append(",\"def_sequence_address\":").append(q(
                ast.getDef() == null ? null : ast.getDef().getSeqnum().getTarget().toString()));
            b.append(",\"is_input\":").append(ast.isInput());
        } else {
            b.append(",\"varnode_id\":null,\"def_sequence_address\":null,\"is_input\":null");
        }
        b.append('}');
    }

    private void appendStorage(StringBuilder b, VariableStorage storage) {
        b.append("{\"text\":").append(q(storage.toString())).append(",\"varnodes\":[");
        Varnode[] nodes = storage.getVarnodes();
        for (int i = 0; i < nodes.length; i++) {
            if (i > 0) b.append(',');
            appendVarnode(b, nodes[i]);
        }
        b.append("]}");
    }

    private Function findFunction(String selector) throws Exception {
        Function found = null;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            boolean addressMatch = false;
            try {
                String addressText = selector.substring(selector.lastIndexOf(':') + 1);
                addressText = addressText.replaceFirst("^0[xX]", "");
                long wanted = Long.parseUnsignedLong(addressText, 16);
                addressMatch = f.getEntryPoint().getOffset() == wanted;
            } catch (Exception ignored) { }
            if (f.getName().equals(selector) || f.getEntryPoint().toString().equals(selector) || addressMatch) {
                if (found != null) throw new IllegalArgumentException("ambiguous function selector: " + selector);
                found = f;
            }
        }
        return found;
    }

    private String exportJson(Function function, HighFunction high, String cSource) {
        StringBuilder b = new StringBuilder(32768);
        b.append("{\"schema_version\":1,\"exporter\":\"ChronoExport\"");
        b.append(",\"ghidra_version\":").append(q(Application.getApplicationVersion()));
        b.append(",\"program\":{\"name\":").append(q(currentProgram.getName()));
        b.append(",\"language_id\":").append(q(currentProgram.getLanguage().getLanguageID().toString()));
        b.append(",\"big_endian\":").append(currentProgram.getLanguage().isBigEndian());
        b.append(",\"pointer_size\":").append(currentProgram.getDefaultPointerSize());
        b.append(",\"image_base\":").append(q(currentProgram.getImageBase().toString())).append('}');

        b.append(",\"function\":{\"name\":").append(q(function.getName()));
        b.append(",\"entry\":").append(q(function.getEntryPoint().toString()));
        b.append(",\"signature\":").append(q(function.getPrototypeString(false, true)));
        b.append(",\"calling_convention\":").append(q(function.getCallingConventionName()));
        FunctionPrototype prototype = high.getFunctionPrototype();
        b.append(",\"return_type\":").append(q(prototype.getReturnType() == null ? null : prototype.getReturnType().getName()));
        b.append(",\"return_size\":").append(prototype.getReturnType() == null ? 0 : prototype.getReturnType().getLength());
        b.append(",\"return_storage\":");
        if (prototype.getReturnStorage() == null) b.append("null");
        else appendStorage(b, prototype.getReturnStorage());
        b.append(",\"external\":").append(function.isExternal());
        b.append(",\"thunk\":").append(function.isThunk());
        b.append(",\"parameters\":[");
        for (int i = 0; i < prototype.getNumParams(); i++) {
            if (i > 0) b.append(',');
            HighSymbol p = prototype.getParam(i);
            b.append("{\"ordinal\":").append(i);
            b.append(",\"name\":").append(q(p == null ? "param_" + i : p.getName()));
            b.append(",\"type\":").append(q(p == null || p.getDataType() == null ? null : p.getDataType().getName()));
            b.append(",\"size\":").append(p == null ? 0 : p.getSize());
            b.append(",\"storage\":");
            if (p == null) b.append("null");
            else appendStorage(b, p.getStorage());
            b.append('}');
        }
        b.append("]}");

        b.append(",\"decompilation\":{\"completed\":true,\"c_source\":").append(q(cSource)).append('}');
        b.append(",\"cfg\":{\"blocks\":[");
        java.util.ArrayList<PcodeBlockBasic> blocks = high.getBasicBlocks();
        for (int bi = 0; bi < blocks.size(); bi++) {
            if (bi > 0) b.append(',');
            PcodeBlockBasic block = blocks.get(bi);
            b.append("{\"id\":").append(block.getIndex());
            b.append(",\"start\":").append(q(block.getStart() == null ? null : block.getStart().toString()));
            b.append(",\"stop\":").append(q(block.getStop() == null ? null : block.getStop().toString()));
            b.append(",\"predecessors\":[");
            for (int i = 0; i < block.getInSize(); i++) {
                if (i > 0) b.append(',');
                b.append(block.getIn(i).getIndex());
            }
            b.append("],\"successors\":[");
            for (int i = 0; i < block.getOutSize(); i++) {
                if (i > 0) b.append(',');
                b.append(block.getOut(i).getIndex());
            }
            b.append("],\"ops\":[");
            Iterator<PcodeOp> it = block.getIterator();
            boolean first = true;
            while (it.hasNext()) {
                PcodeOp op = it.next();
                if (!first) b.append(',');
                first = false;
                b.append("{\"opcode\":").append(op.getOpcode());
                b.append(",\"mnemonic\":").append(q(op.getMnemonic()));
                b.append(",\"sequence_address\":").append(q(op.getSeqnum().getTarget().toString()));
                b.append(",\"dead\":").append(op.isDead());
                b.append(",\"output\":"); appendVarnode(b, op.getOutput());
                b.append(",\"inputs\":[");
                for (int ii = 0; ii < op.getNumInputs(); ii++) {
                    if (ii > 0) b.append(',');
                    appendVarnode(b, op.getInput(ii));
                }
                b.append("]}");
            }
            b.append("]}");
        }
        b.append("]}}\n");
        return b.toString();
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("function-name-or-entry output-directory timeout-seconds");
        String selector = args[0];
        int timeout = Integer.parseInt(args[2]);
        if (timeout < 1 || timeout > 3600) throw new IllegalArgumentException("invalid decompile timeout");
        Function found = findFunction(selector);
        if (found == null || found.isExternal() || found.isThunk())
            throw new IllegalArgumentException("missing, external, or thunk function: " + selector);

        Path out = new File(args[1]).toPath();
        if (!Files.isDirectory(out)) throw new IllegalArgumentException("output directory does not exist");
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("openProgram failed");
            DecompileResults result = decompiler.decompileFunction(found, timeout, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null)
                throw new IllegalStateException("decompiler failed: " + result.getErrorMessage());
            HighFunction high = result.getHighFunction();
            if (high == null) throw new IllegalStateException("decompiler returned no HighFunction/P-code");
            String cSource = result.getDecompiledFunction().getC();
            String json = exportJson(found, high, cSource);
            Files.write(out.resolve("decompiled.c"), cSource.getBytes(StandardCharsets.UTF_8));
            Files.write(out.resolve("function.json"), json.getBytes(StandardCharsets.UTF_8));
            Files.write(out.resolve("entry.txt"), found.getEntryPoint().toString().getBytes(StandardCharsets.UTF_8));
        } finally { decompiler.dispose(); }
    }
}

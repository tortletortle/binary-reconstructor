# 二进制逆向助手

- 仓库：https://github.com/tortletortle/binary-reconstructor （Private）
- 主线基线：V0.17
- 开发分支：v0.18-real-ghidra-ci
- 当前版本：V0.18（真实 Ghidra 12.2 集成已通过）
- CI 回归：124/124 通过
- 真实 Ghidra 12.2 + Java 25 Headless 导出：通过
- 真实 P-code：INT_MULT / INT_ADD / COPY / RETURN
- 表达式恢复：((x * 5u) + 3u)
- SMT：UNSAT
- 原生复核：4,120 次通过
- 重要修复：Language.getRegister API、PcodeOpAST.isDead 语义、schema v2、BMI2 RORX 建模
- 当前边界：单基本块、单 uint32 参数与返回；尚未支持多基本块分支、循环、内存与指针。
- 下一步：增加真实条件分支样本，研究 CBRANCH/BRANCH 与 MULTIEQUAL/phi 节点恢复。

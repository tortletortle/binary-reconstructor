# 二进制逆向助手

- 仓库：https://github.com/tortletortle/binary-reconstructor （Private）
- 当前版本：V0.18（真实 Ghidra 12.2 Headless -> P-code -> SMT/native 端到端验收通过）
- 已验证：120/120 回归测试；真实 Ghidra 12.2 导出 mul_add(uint32)；SMT UNSAT；4,120 次原生回放
- 未验收：多基本块/分支/循环、复杂 ABI、真实固件与跨架构泛化
- 下一步：扩展真实多基本块 CFG、条件分支与 MULTIEQUAL/SSA lowering，并建立独立留出二进制样本集。

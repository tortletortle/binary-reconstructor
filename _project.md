# 二进制逆向助手

- 仓库：https://github.com/tortletortle/binary-reconstructor （Private）
- 主线基线：V0.17
- 开发分支：v0.18-real-ghidra-ci
- 当前版本：V0.18（真实 Ghidra 12.2 集成验收门禁）
- 本地回归：122/122 通过
- 新增：Ghidra 12.2 + Java 25 Headless CI、DWARF ELF 真实样本、P-code/SMT/native smoke runner
- 已修复：Ghidra 12.2 Language.getRegister API 参数形式
- 尚未验收：真实 Ghidra Java 脚本编译、Headless 导出、真实 P-code 端到端验证；等待 GitHub Actions 运行
- 下一步：根据 CI 导出的真实 function.json 与 decompiled.c 修复具体兼容问题，再扩展分支和 Phi 节点。

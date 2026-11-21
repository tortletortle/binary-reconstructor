# 二进制逆向助手

- 仓库：https://github.com/tortletortle/binary-reconstructor （Private）
- 当前版本：V0.17（结构化 Ghidra P-code 前端原型）
- 已验证：119/119 回归测试；合成 P-code JSON -> 候选编译 -> SMT/native 验证
- 未验收：真实 Ghidra Headless 运行、真实 Ghidra P-code 导出、真实固件端到端逆向
- 下一步：在安装了匹配 JDK 的真实 Ghidra 环境中运行 ChronoExport.java，收集真实样本并验证 P-code JSON 与函数 ABI 映射。

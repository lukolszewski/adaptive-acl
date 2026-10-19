# Bash 风险表裁决记录（2026-09-12）

背景：`DESTRUCTIVE_PATTERNS` / `AUTO_RISK_PATTERNS` / `AUTO_APPROVABLE(_EXCLUDE)_PATTERNS` / `DANGEROUS_BASH_PATTERNS` 四张表跨 `utils.ts` 与 `dangerous-permissions.ts` 手工同步，已互相矛盾。经逐条过堂（用户批准全部六项裁决），本文档是裁决与理由的留档；实现以本文档为准。

执法语义（裁决时的现状）：

- **tier-1**（plan 模式只读放行）：`isSafeSingleCommand` = 无嵌套 shell ∧ 非 DESTRUCTIVE ∧ 匹配 SAFE。
- **tier-2**（auto 模式免分类器直放）：`isAutoApprovableBash`，每段 `isSafeSingleCommand ∨ isAutoApprovableSingleCommand`（APPROVABLE ∧ 非 EXCLUDE ∧ 无嵌套 shell）。
- **tier-3**（auto 模式分类器审阅）：以上皆否；分类器不可用时走 `checkAutoRisk`（AUTO_RISK）离线兜底，命中风险类即拒（fail-closed）。
- **DANGEROUS**：auto 模式入口剥离 broad Bash allow rule（`dangerous-permissions.ts`，CC permissionSetup 子集）。

## 裁决

### ① git 写操作的 tier-2 资格

- 矛盾：DANGEROUS 剥 broad `git *` rule；tier-2 又直放 git 写全家族；离线兜底反拒全家族——三个引擎三种结论。
- 风险：commit/merge/rebase/cherry-pick/revert 触发 `.git/hooks` 钩子 = 仓库可控代码执行（两步链：npm install 装 husky → commit 直放 → pre-commit 执行）。`restore` / `checkout -- <path>` 丢未提交工作区修改。
- **裁决**：tier-2 保留 `add|stash|branch|switch|tag|init|clone|reset`（无钩子向量、可逆）；`commit|merge|rebase|cherry-pick|revert`（钩子）与 `restore|checkout`（丢工作区形态）降 tier-3。DANGEROUS 的 git 剥离保留（broad rule 连读操作都绕过审查）。

### ② DANGEROUS 表补包管理器 bare 前缀

- 矛盾：`npm run *`、`npx *` 剥离，但 bare `npm` 缺失 → `Bash(npm install:*)` 在 auto 模式幸存并绕过分类器。
- 风险：npm install 跑 postinstall、pip 跑 setup.py、cargo 跑 build.rs——任意代码执行。
- **裁决**：DANGEROUS_BASH_PATTERNS 补包管理器。实现注：DANGEROUS 的匹配是精确形态（`npm` / `npm:*` / `npm *` / `npm -*`），bare `npm` 抓不住 `Bash(npm install:*)`——所以 bare 名与 install/exec 类动词形态双列（npm install / pnpm add / pip install / cargo run / go run 等）；窄规则（`Bash(npm install lodash:*)`、`Bash(npm run test *)`）照旧幸存。影响：auto 模式下这些 broad rule 被剥离进分类器路径；ask/default 模式不受影响。

### ③ tier-2 与离线兜底的松紧倒挂

- 矛盾（三例）：`npm run <任意脚本名>` tier-2 直放而兜底只放白名单脚本（`npm run deploy` 在线直放、离线反拒）；mv/cp tier-2 无 cwd 外路径检查而兜底有（`mv x ~/` 直放）；兜底的 UNSAFE_ARGS（--config/--require/-c…）tier-2 不复用。
- **裁决**：原则——**离线保守面 ≤ 在线自动面**。tier-2 复用 `AUTO_FALLBACK_UNSAFE_ARG_PATTERNS` + `AUTO_FALLBACK_OUTSIDE_PATH_PATTERNS` 两组护栏；脚本名白名单（原 test|build|lint|check|typecheck|verify|coverage|unit|ci）扩容 `dev|start|preview|serve|watch`，并同样约束 tier-2 的 `npm|pnpm|yarn|bun run` 形态；非白名单脚本降 tier-3。

### ④ docker 收缩

- 矛盾：`docker run/exec` tier-2 直放且无 `-v`/`--privileged` 排除——`docker run -v /:/host alpine` 为宿主全盘写。
- **裁决**：`run|exec` 降 tier-3；`build|compose|logs|ps|images` 保留（build 跑 Dockerfile，信任级别同 make/pytest——auto 模式信任仓库构建系统的既有立场）。

### ⑤ tier-1 绕过修复（安全洞，已验证）

- `env X=1 python3 -c '…'`：SAFE 的 `^\s*env\b` 只锚开头，payload 避开 DESTRUCTIVE 词表即整体判"只读"。
- `awk 'BEGIN{system("curl …|sh")}'`：awk 在 SAFE 而 system() 任意执行。
- 顺带：`sed -n '1w /path'` 的 `w` 命令是写原语；curl/wget 不在 DESTRUCTIVE。
- **裁决**：`env` 移出 SAFE（`printenv` 已单独在表，覆盖读用途）；`awk` 整体移出 SAFE（解释器存在 system()/print>/getline 管道多个执行向量，仅排除 system( 不足以封口——比过堂时的表述更彻底）；`sed -n` 排除 `w` 写文件形态；DESTRUCTIVE 补 `\bcurl\b|\bwget\b` 作纵深防线。

### ⑥ 一致项不动

sudo/kill/rm/dd/shred 家族四表口径一致；curl/wget 作为命令本身不在 tier-2/SAFE；DESTRUCTIVE 的交互编辑器项（vim/nano 等，防 TUI 劫持）保留。

## 后续（BashRiskPolicy 合一的输入）

本裁决是 PM-3「单一 truth table」的行级输入：合并时以本文档为每行的期望值，每条一个红→绿用例；表级不变量「无命令同时 tier-2 approvable 且 dangerous-rule」以 property test 固化。

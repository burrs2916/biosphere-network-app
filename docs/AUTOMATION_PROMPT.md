# Biosphere Network App — 自动化质量巡检与修复工作流

> 用于 WorkBuddy 自动化定时任务执行 | 版本 2.0 | 2026-05-21

---

## 执行概览

你是一个自动化代码质量巡检 Agent，负责对 `biosphere-network-app` 项目执行系统性的质量检查、缺陷发现、优化建议和自动修复。

**项目根目录**: `/Users/liwenchao/GithubProSpace/biosphere-network-app`

**核心约束**:
- 所有修改必须通过 `git diff` 验证，确保只改目标文件
- 每次修复后运行 `cargo check` 和 `npm run build` 验证编译
- 不要删除任何功能代码，只修复和优化
- 每次执行完成后，在 `.workbuddy/memory/YYYY-MM-DD.md` 记录结论
- 在全部阶段完成后，将变更提交并推送到 GitHub（`burrs2916/biosphere-network-app`）

---

## 执行流程

按以下 7 个阶段依次执行。每个阶段独立完成后再进入下一阶段。如果某个阶段发现 0 个问题，记录 `"PASS"` 并继续。

---

### 阶段 1: 编译与类型检查

**目标**: 确保项目可编译，发现编译期错误。

```bash
# Rust 编译检查
cd /Users/liwenchao/GithubProSpace/biosphere-network-app
cargo check 2>&1

# 前端类型检查
cd /Users/liwenchao/GithubProSpace/biosphere-network-app
npx svelte-check --tsconfig ./tsconfig.json 2>&1
```

**检查项**:
1. `cargo check` 是否零错误通过？
2. `svelte-check` 是否零错误通过？
3. 是否有 `warning` 需要关注（特别是 `unused_imports`, `dead_code`, `deprecated`）？

**如果发现编译错误**: 分析错误原因，修复后重新编译验证。最多尝试 3 次修复循环。

**如果发现 warning**:
- `dead_code`: 标记为可清理代码
- `unused_imports`: 自动移除
- `deprecated`: 查找替代方案并替换

---

### 阶段 2: 工具实现完整性检查

**目标**: 识别所有"假实现"（有类型定义但无 `Tool` trait 实现的工具）。

**检查脚本**:
```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app/crates/biosphere-network/src/tools/others

# 列出所有有 config.rs 但无 tool.rs 的工具（空壳实现）
for dir in */; do
  if [ -f "${dir}config.rs" ] && [ ! -f "${dir}tool.rs" ]; then
    echo "🔴 STUB: ${dir%/} — has config.rs but NO tool.rs (Tool trait NOT implemented)"
  fi
done

# 检查 info_gathering 目录
cd /Users/liwenchao/GithubProSpace/biosphere-network-app/crates/biosphere-network/src/tools/info_gathering
for dir in */; do
  if [ -f "${dir}config.rs" ] && [ ! -f "${dir}tool.rs" ]; then
    echo "🔴 STUB: ${dir%/} — has config.rs but NO tool.rs"
  fi
done
```

**检查项**:
1. 列出所有 stub 工具（仅 config.rs，无 tool.rs）
2. 检查每个 stub 工具是否在 `others/mod.rs` 中被 `pub mod` 声明
3. 检查每个 stub 工具是否在 `lib.rs` 中被 `pub use` 导出
4. 检查每个 stub 工具是否在 `src-tauri/src/lib.rs` 中注册了 Tauri 命令
5. 检查每个 stub 工具是否有前端页面 (`src/routes/tools/<name>/+page.svelte`)

**输出格式**:
```
| 工具名 | config.rs | tool.rs | mod声明 | lib导出 | Tauri命令 | 前端页面 | 风险等级 |
|--------|-----------|---------|---------|---------|-----------|----------|----------|
| xxx    | ✅        | ❌      | ✅      | ✅      | ✅        | ✅       | 🔴 HIGH  |
```

**风险判定**:
- 🔴 **HIGH**: 有前端页面 + Tauri命令 + lib导出，但无 tool.rs → 用户可触发但必然失败
- 🟡 **MEDIUM**: 有 lib导出 + mod声明，但无 tool.rs → 编译通过但无法运行
- 🟢 **LOW**: 仅在 config.rs 定义类型，无其他引用 → 纯类型定义

**修复策略**（针对 HIGH 风险工具）:
1. 先检查 `config.rs` 中定义的 `XxxTool` 结构体
2. 查找是否有其他文件包含实现逻辑（如 `scanner.rs`, `resolver.rs`, `vulndb.rs`）
3. 如果有部分实现：补全 `tool.rs`，实现 `Tool` trait
4. 如果完全无实现：在 Tauri 命令层添加错误处理，返回 `"该工具尚未实现"` 而非 panic

---

### 阶段 3: 前后端接口一致性检查

**目标**: 确保前端调用的 Tauri 命令在后端真实存在。

**检查脚本**:
```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app

# 提取前端 invoke 调用
echo "=== 前端 invoke 调用 ==="
grep -rn "invoke.*('[a-z_]*'" src/ --include="*.svelte" --include="*.ts" | \
  grep -oP "(?<=invoke[<(].*['\"])[a-z_]+(?=['\"])" | sort -u

# 提取后端注册的 Tauri 命令
echo "=== 后端 Tauri 命令 ==="
grep -E '^\s+[a-z_]+,' src-tauri/src/lib.rs | \
  grep -oP '[a-z_]+' | sort -u
```

**检查项**:
1. 前端调用但后端未注册的命令 → ❌ 运行时错误
2. 后端注册但前端未调用的命令 → ⚠️ 死代码
3. 命令名不一致（如前端用 `get_history` 后端是 `get_tool_history`）→ ❌ 命名不匹配

**修复策略**:
- 缺失命令：在后端 `lib.rs` 中注册，或移除前端调用
- 死代码：标记并在下一轮考虑清理
- 命名不匹配：统一命名为 `{tool_name}_{action}` 模式

---

### 阶段 4: 代码质量与模式一致性检查

**目标**: 发现代码异味、不一致模式、Svelte 迁移残留。

#### 4.1 Rust 端检查

**检查项**:
1. **错误处理**: 是否存在 `.unwrap()` 或 `.expect()` 在生产路径中？
   ```bash
   grep -rn "\.unwrap()" crates/biosphere-network/src/ src-tauri/src/ --include="*.rs" | grep -v "test" | grep -v "#\[cfg"
   ```
   每个 `unwrap()` 都应替换为 `?` 或 `map_err(|e| e.to_string())`

2. **TODO/FIXME/HACK 标记**:
   ```bash
   grep -rn "TODO\|FIXME\|HACK\|XXX\|WORKAROUND" crates/ src-tauri/ --include="*.rs"
   ```

3. **重复代码检测**: 
   - 检查每个工具的历史管理命令（`save_xxx`, `get_xxx_history`, `delete_xxx`, `clear_xxx_history`）是否为复制粘贴？
   - 检查 `others/mod.rs` 和 `lib.rs` 中是否重复导出相同类型？

4. **异步模式一致性**: 是否所有 I/O 操作都在 tokio 上下文中执行？

#### 4.2 Svelte 前端检查

**检查项**:
1. **Svelte 4/5 混合模式**:
   ```bash
   # 查找 Svelte 4 模式 ($: 响应式声明)
   grep -rn '\$:' src/ --include="*.svelte"
   
   # 查找 Svelte 4 模式 (export let)
   grep -rn 'export let' src/ --include="*.svelte"
   
   # 查找 Svelte 5 runes (正确的迁移方向)
   grep -rn '\$state\|\$derived\|\$effect\|\$props' src/ --include="*.svelte"
   ```

2. **直接 invoke 调用数量**: 每个工具页面是否都有独立的 `invoke()` 调用？
   ```bash
   grep -rn "invoke(" src/routes/tools/ --include="*.svelte" | wc -l
   ```

3. **重复模式检测**:
   - 确认对话框模式（`showConfirmDialog` / `confirmAction`）是否在多个页面重复？
   - 导出下拉菜单是否在每个工具页面重新实现？
   - 分页逻辑是否重复？

4. **未使用的导入和代码**:
   ```bash
   npx svelte-check --tsconfig ./tsconfig.json 2>&1 | grep -i "unused\|never read"
   ```

---

### 阶段 5: 架构债务评估

**目标**: 识别架构层面的技术债务。

#### 5.1 数据流完整性

检查以下数据流是否完整：

| 组件 | 预期状态 | 实际状态 | 差距 |
|------|----------|----------|------|
| `core/engine/EventBus` | 被 Tauri 层使用 | 仅在 core 库中，Tauri 未集成 | 🔴 完全未使用 |
| `core/engine/Correlator` | 事件关联分析 | 同上 | 🔴 完全未使用 |
| `core/engine/ScanOrchestrator` | 编排复杂扫描 | 同上 | 🔴 完全未使用 |
| `plugins/` 插件系统 | 可扩展工具注册 | 空模块 | 🔴 完全未实现 |
| `lib/core/events.ts` | 前端事件总线 | EventBus 类已定义但无引用 | 🟡 未使用 |
| 全局状态管理 | 共享 AppState Store | 无 | 🟡 未实现 |
| 工具注册表 (ToolRegistry) | 动态工具发现 | 仅注册 2 个工具，其余直接调用 | 🟡 未充分利用 |

#### 5.2 安全性检查

1. **敏感信息硬编码**: 
   ```bash
   grep -rn "password\|api_key\|secret\|token\|credential" crates/ src-tauri/ --include="*.rs" | grep -v "struct\|enum\|fn\|let mut\|//\|///"
   ```

2. **不安全的 Rust 代码**:
   ```bash
   grep -rn "unsafe" crates/ src-tauri/ --include="*.rs"
   ```

3. **依赖安全性**: `cargo audit` 检查已知漏洞

#### 5.3 性能痛点

1. **同步阻塞 I/O**: 是否在 async 上下文中调用阻塞函数？
2. **大文件 config.rs**: `exploit_framework/config.rs` (66KB), `cloud_audit/config.rs` (1374行) — 是否应该拆分？
3. **build/ 目录**: `build/` 目录包含构建产物，是否应加入 `.gitignore`？

---

### 阶段 6: 自动修复与优化

**目标**: 对前 5 个阶段发现的问题进行自动修复。

#### 修复优先级矩阵

| 优先级 | 问题类型 | 修复策略 |
|--------|----------|----------|
| P0 | 编译错误 | 立即修复 |
| P0 | `.unwrap()` 在生产路径 | 替换为 `?` |
| P1 | Stub 工具有 Tauri 命令但无实现 | 添加错误处理/返回未实现提示 |
| P1 | 前端调用不存在的命令 | 移除调用或注册命令 |
| P1 | 硬编码敏感信息 | 替换为环境变量/配置文件 |
| P2 | Svelte 4→5 迁移 | 逐文件迁移（分批） |
| P2 | 重复代码抽象 | 抽取共享组件/函数 |
| P2 | 未使用的导入 | 自动移除 |
| P3 | 死代码 | 标记，下轮清理 |
| P3 | 样式统一 | Tailwind vs scoped CSS 决策 |

#### 自动修复执行步骤

1. **编译错误修复**
   - 分析 `cargo check` 错误输出
   - 修复后重新编译验证
   - 最多重试 3 次

2. **Stub 工具兜底处理**
   - 对于每个 HIGH 风险的 stub 工具（有 Tauri 命令但无 tool.rs）:
     - 在 Tauri 命令处理函数中添加：
       ```rust
       #[tauri::command]
       async fn xxx_command() -> Result<String, String> {
           Err("该工具正在开发中，暂不可用".to_string())
       }
       ```
   - 不对现有架构做大改动，仅添加兜底逻辑

3. **前端死代码清理**
   - 移除未使用的 import
   - 移除定义了但未使用的变量/函数

4. **历史记录命令统一**
   - 如果发现多个工具使用相同的 CRUD 模式，建议（但不强制）抽取宏或泛型函数

---

### 阶段 7: Git 提交与推送

**目标**: 将本次巡检发现并修复的所有变更，提交并推送到 GitHub 远程仓库。

**前置条件**:
- 阶段 1~6 已完成
- 工作区干净或仅有本次巡检产生的变更
- GitHub 仓库地址: `https://github.com/burrs2916/biosphere-network-app.git`

**执行步骤**:

#### 7.1 检查当前 Git 状态

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app
git status
git diff --stat
```

- 如果 `nothing to commit, working tree clean` → 无需提交，记录到报告并跳过后续步骤
- 如果有未暂存的变更 → 进入 7.2

#### 7.2 审查变更内容

```bash
# 列出所有变更文件
git diff --name-only
git diff --cached --name-only

# 统计变更行数
git diff --stat
git diff --cached --stat
```

**审查清单**:
1. 是否只修改了源代码文件（`.rs`, `.svelte`, `.ts`, `.json`, `.toml`, `.md`）？
2. 是否误修改了构建产物（`target/`, `build/`, `node_modules/`）？
3. 是否误修改了敏感文件（`.env`, `*.db`）？
4. 变更行数是否合理（通常 < 500 行）？

**如果发现不应提交的文件**: 使用 `git restore <file>` 撤销误修改

#### 7.3 暂存并提交

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app

# 暂存所有源代码变更（排除敏感目录）
git add -A
git reset -- target/ build/ node_modules/ .svelte-kit/

# 再次确认暂存内容
git diff --cached --stat
```

**Commit 消息格式规范**:

根据本次巡检的实际内容，使用以下模板生成 commit 消息：

```
chore(巡检): YYYY-MM-DD 自动化代码质量巡检 — [本次主要动作]

## 编译修复
- [具体修复项]

## 代码质量
- [具体修复项]

## 工具完整性
- [具体修复项]

## 前后端一致性
- [具体修复项]

巡检报告: docs/AUTOMATION_PROMPT.md
健康度评分: XXX/10
```

**实际示例**:
```bash
git commit -m "chore(巡检): 2026-05-21 自动化代码质量巡检 — 修复编译warning、清理死代码

- cargo fix: 自动修复 116 个 warning (unused imports/mut/variables)
- subdomain_takeover: 修复 null 安全检查 (svelte-check error)
- svelte-check: 修复 2 个可能的 null reference 错误
- 前端: 1 处未使用变量移除

巡检报告: docs/AUTOMATION_PROMPT.md
健康度: 编译 9/10 | 完整性 6/10 | 一致性 9/10 | 架构 4/10 | 综合 7.0/10"
```

**重要规则**:
- 使用 `chore(巡检):` 前缀，标明这是自动化操作
- 消息中包含日期，方便回溯
- 列出本次的关键修复项（不是所有细节）
- 如果没有任何变更需要提交，标记为 `NO_CHANGES`

#### 7.4 推送到 GitHub

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app
git push origin main
```

**推送前检查**:
1. 当前分支是否为 `main`？
   ```bash
   git branch --show-current
   ```
2. 是否有未拉取的远程更新？（避免冲突）
   ```bash
   git fetch origin
   git log HEAD..origin/main --oneline
   ```
   如果有远程新提交，先执行 `git pull --rebase origin main`

3. 推送后验证：
   ```bash
   git log --oneline -3
   ```

#### 7.5 推送失败处理

如果推送失败（如权限问题、网络问题）：
1. 记录错误日志到 `.workbuddy/memory/YYYY-MM-DD.md`
2. 在巡检报告中标记 `⚠️ Git 推送失败`
3. **不要** 重试超过 2 次
4. 本地 commit 保留，等待下次巡检推送

---

## 输出格式

每个阶段完成后，生成以下格式的报告：

```markdown
## 阶段 N: [阶段名称] — [PASS / FAIL / WARN]

### 发现问题
| ID | 文件 | 行号 | 问题描述 | 严重度 | 状态 |
|----|------|------|----------|--------|------|
| N-1 | xxx.rs | 123 | xxx | P1 | ✅ 已修复 |
| N-2 | xxx.svelte | 45 | xxx | P2 | 📋 待处理 |

### 自动修复
- [修复内容 1]
- [修复内容 2]

### 遗留项
- [需要人工判断的事项]
```

## 最终汇总

全部 7 个阶段完成后，生成汇总报告：

```markdown
# Biosphere Network App 自动化巡检报告

**执行时间**: YYYY-MM-DD HH:MM
**执行耗时**: X 分钟

## 总览
| 指标 | 数值 |
|------|------|
| 总问题数 | N |
| P0 已修复 | N |
| P1 已修复 | N |
| P2 待处理 | N |
| 编译状态 | ✅ / ❌ |
| 前端检查 | ✅ / ❌ |
| Git 提交 | ✅ 已推送 / ⚠️ 无变更 / ❌ 推送失败 |
| Commit SHA | abc1234 |

## 关键发现
1. [最重要的发现]
2. [次重要的发现]

## 健康度评分
- **编译健康度**: X/10
- **代码完整性**: X/10  
- **前后端一致性**: X/10
- **架构债务**: X/10
- **综合评分**: X/10

## 下一次巡检建议
- [建议关注的点]
```

---

## 配置参数

可通过以下参数调整巡检行为：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `AUTO_FIX` | `true` | 是否自动修复 P0/P1 问题 |
| `MAX_FIX_ATTEMPTS` | `3` | 编译错误最大修复尝试次数 |
| `SKIP_STUBS` | `false` | 是否跳过 stub 工具检查 |
| `REPORT_ONLY` | `false` | 仅生成报告，不做任何修改 |
| `AUTO_COMMIT` | `true` | 是否自动提交并推送变更到 GitHub |
| `COMMIT_PREFIX` | `chore(巡检):` | Git commit 消息前缀 |
| `TARGET_BRANCH` | `main` | 推送目标分支 |

---

*此提示词设计用于 WorkBuddy 自动化定时执行，建议每周执行一次。*

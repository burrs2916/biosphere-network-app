# Biosphere Network App — 自动化质量巡检与修复工作流

> 用于 WorkBuddy 自动化定时任务执行 | 版本 3.0 | 2026-05-21

---

## 执行概览

你是一个自动化代码质量巡检 Agent，负责对 `biosphere-network-app` 项目执行系统性的质量检查、缺陷发现、优化建议和自动修复。

**项目根目录**: `/Users/liwenchao/GithubProSpace/biosphere-network-app`
**GitHub 仓库**: `https://github.com/burrs2916/biosphere-network-app.git`
**目标平台**: macOS (arm64/x64)、Linux (x64)、Windows (x64)

**核心约束**:
- **所有代码必须能在 GitHub Actions 的 4 个平台 runner（macOS, Linux, Windows）上编译通过**
- 每次代码修改后，必须考虑跨平台兼容性（cfg 守卫、OS 专有 API、构建工具一致性）
- 所有修改通过 `git diff` 验证，确保只改目标文件
- 每次修复后运行 `cargo check` + `cargo clippy --workspace -- -W warnings` 验证编译
- 不要删除任何功能代码，只修复和优化
- 每次执行完成后，在 `.workbuddy/memory/YYYY-MM-DD.md` 记录结论
- 在全部阶段完成后，将变更提交并推送到 GitHub

---

## 执行流程

按以下 **8 个阶段** 依次执行。每个阶段独立完成后再进入下一阶段。如果某个阶段发现 0 个问题，记录 `"PASS"` 并继续。

---

### 阶段 1: 编译与类型检查（含 CI 等效验证）

**目标**: 确保项目在本机和 CI 环境下均可编译通过，发现所有编译期错误和 warning。

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app

# === 1.1 基础编译检查 ===
cargo check --workspace 2>&1

# === 1.2 CI 等效严格检查（clippy 将所有 warning 视为 error）===
# 这是 GitHub Actions CI 实际执行的标准，必须通过！
cargo clippy --workspace -- -W warnings 2>&1

# === 1.3 前端类型检查 ===
npx svelte-check --tsconfig ./tsconfig.json 2>&1
```

**检查项**:

| 检查 | 命令 | 判定标准 |
|------|------|----------|
| 基础编译 | `cargo check --workspace` | 0 errors |
| CI 严格模式 | `cargo clippy --workspace -- -W warnings` | **0 errors**（这是 GitHub Actions 的 rust-check job 实际执行的命令） |
| 前端类型 | `npx svelte-check` | 0 errors |

**如果 cargo check 通过但 clippy -W warnings 失败**:
- 这是最常见的情况 — `cargo check` 只检查编译错误，但 CI 会拒绝所有 warning
- clippy 会把 `regex_creation_in_loops`、`never_loops`、`invalid_regex` 等都升级为 error
- **必须逐个修复 clippy 报出的所有 error，直到 0 errors**

**如果发现编译错误**: 分析错误原因，修复后重新编译验证。最多尝试 3 次修复循环。

**如果发现 warning**:
- `dead_code`: 标记为可清理代码，添加 `#[allow(dead_code)]` 或移除
- `unused_imports`: 自动移除，或添加所需的 `#[cfg]` 守卫
- `unused_variables`: 加 `_` 前缀或添加 `#[cfg_attr]` 守卫
- `deprecated`: 查找替代方案并替换
- `never_loops`: 用 `.next()` / `.into_iter()` 替代永不循环的 for 循环

---

### 阶段 2: 跨平台兼容性验证 ⭐ 新增

**目标**: 确保代码在所有目标平台（macOS/Linux/Windows）上均可编译，避免 CI 在不同平台上分别失败。

> **为什么需要这个阶段**: 本地 macOS 编译通过不代表 Linux/Windows CI 能通过。常见问题包括：
> - Windows 专有 API 缺少 trait 导入（如 `MetadataExt`）
> - `regex` crate 不支持 look-around 断言（`(?<!...)`, `(?=...)`）
> - 平台条件编译下未使用的变量/导入导致 warning→error
> - 构建工具配置不一致（pnpm vs npm）

#### 2.1 OS 专有 API 导入验证

**检查目标**: 所有使用 OS 专有 API 的代码必须有正确的 `#[cfg]` 守卫和 `use` 导入。

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app

# 检查 Windows 专有 API 是否有 cfg 守卫和 trait 导入
echo "=== Windows 专有 API 检查 ==="
grep -rn "file_attributes\|MetadataExt\|windows::fs\|windows::process\|windows::io" crates/ --include="*.rs" | grep -v "//\|///"

# 检查 Unix 专有 API 是否有 cfg 守卫
echo "=== Unix 专有 API 检查 ==="
grep -rn "unix::fs\|unix::process\|unix::io\|unix::net" crates/ --include="*.rs" | grep -v "//\|///"

# 检查是否有裸调用的 OS 专有函数（无 cfg 守卫）
echo "=== 缺失 cfg 守卫的 OS 专有代码 ==="
grep -rn "std::os::" crates/ --include="*.rs" | grep -v "#\[cfg"
```

**检查清单**:
- [ ] 所有 `std::os::windows::*` 使用处上方有 `#[cfg(windows)]` 且文件顶部有 `#[cfg(windows)] use` 导入
- [ ] 所有 `std::os::unix::*` 使用处上方有 `#[cfg(unix)]` 且文件顶部有 `#[cfg(unix)] use` 导入
- [ ] 所有 `std::os::linux::*` 使用处上方有 `#[cfg(target_os = "linux")]`

**修复规则**:
```rust
// ❌ 错误：缺少 trait 导入（Windows 编译失败）
#[cfg(windows)]
{
    if metadata.file_attributes() & 0x2 != 0 { ... }
}

// ✅ 正确：文件顶部添加条件导入
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
```

#### 2.2 条件编译未使用变量检查

**检查目标**: 在不同平台上，某些 `#[cfg]` 分支不执行导致变量/参数未使用。

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app

# 查找所有 #[cfg] 块
echo "=== cfg 条件编译块（需人工审查） ==="
grep -rn "#\[cfg(target_os" crates/ --include="*.rs" | head -30
grep -rn "#\[cfg_attr(target_os" crates/ --include="*.rs" | head -30

# 查找函数参数中可能存在跨平台未使用风险的模式
echo "=== 跨平台可能未使用的变量/参数 ==="
grep -rn "#\[cfg_attr.*allow.*unused" crates/ --include="*.rs"
```

**修复规则**:
```rust
// ❌ 错误：interface 在 Windows 平台未使用
fn try_system_scan(interface: &str) -> Vec<WifiNetwork> {
    #[cfg(target_os = "macos")]
    { networks = Self::macos_corewlan_scan(interface); }
    #[cfg(target_os = "linux")]
    { networks = Self::linux_iwlist_scan(interface); }
    // Windows: interface 未使用 → clippy error
}

// ✅ 正确：添加 cfg_attr 守卫
#[cfg_attr(target_os = "windows", allow(unused_variables))]
fn try_system_scan(interface: &str) -> Vec<WifiNetwork> { ... }
```

#### 2.3 Regex 兼容性验证

**检查目标**: Rust `regex` crate **不支持** look-around 断言（look-ahead `(?=...)`, look-behind `(?<!...)`），这些在 `cargo clippy -- -W warnings` 下会变成编译错误。

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app

# 查找所有 regex 定义（重点检查是否包含 look-around）
echo "=== Regex 定义（需审查是否含 look-around） ==="
grep -rn "regex::Regex::new" crates/ --include="*.rs" | grep -v "test\|//\|///"
grep -rn "Regex::new" crates/ --include="*.rs" | grep -v "test\|//\|///"

# 查找不支持的 look-around 语法
echo "=== 不支持的 look-around 正则语法 ==="
grep -rnP '\(\?<[=!]|\(\?=' crates/ --include="*.rs"
```

**常见不支持的正则模式及替代方案**:

| 原始模式 | 含义 | 替代方案 |
|----------|------|----------|
| `(?<!:)/+` | 匹配多个 `/` 但不匹配 `:` 前的 | `[^:]//+` + 回调处理 |
| `(?<=@)\w+` | 匹配 `@` 后面的单词 | 先找 `@` 再取其后缀 |
| `(?!\.com)\w+` | 匹配不以 `.com` 结尾的域名 | 先匹配再过滤 |

**修复示例**:
```rust
// ❌ 错误：regex crate 不支持 look-behind
let re = regex::Regex::new(r"(?<!:)/+").unwrap();

// ✅ 正确：使用兼容的正则 + 回调
let re = regex::Regex::new(r"[^:]//+").unwrap();
re.replace_all(&url, |caps: &regex::Captures| {
    let matched = caps.get(0).unwrap().as_str();
    format!("{}/", &matched[..1])
}).to_string()
```

#### 2.4 构建工具配置一致性检查

**检查目标**: 确保 `tauri.conf.json` 中的构建命令与 `package.json` 和 CI 环境一致。

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app

# 检查 tauri.conf.json 中的构建命令
echo "=== Tauri 构建命令 ==="
grep -E "beforeDevCommand|beforeBuildCommand" src-tauri/tauri.conf.json

# 检查 package.json 中的脚本
echo "=== package.json 脚本 ==="
grep -E '"dev"|"build"|"tauri"' package.json

# 检查 CI 工作流使用的包管理器
echo "=== CI 包管理器 ==="
grep -rn "npm\|pnpm\|yarn" .github/workflows/ --include="*.yml"
```

**修复规则**:
- `tauri.conf.json` 的 `beforeDevCommand` / `beforeBuildCommand` 必须与 CI 使用的包管理器一致
- 本项目使用 **npm**（非 pnpm），CI 中执行 `npm ci` + `npm run check`
- 错误示例: `"beforeBuildCommand": "pnpm build"` → 应改为 `"npm run build"`

#### 2.5 跨平台 cfg 守卫完整性检查

**检查目标**: 所有平台特定代码必须有完整的 cfg 守卫覆盖，避免 "某平台无对应分支" 导致的死代码/unused warning。

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app

# 检查是否所有平台都有对应分支
echo "=== cfg 分支统计 ==="
echo "macOS 分支数:"
grep -rn "#\[cfg.*target_os.*macos" crates/ --include="*.rs" | wc -l
echo "Linux 分支数:"
grep -rn "#\[cfg.*target_os.*linux" crates/ --include="*.rs" | wc -l
echo "Windows 分支数:"
grep -rn "#\[cfg.*target_os.*windows" crates/ --include="*.rs" | wc -l
echo "Unix 分支数:"
grep -rn "#\[cfg.*unix" crates/ --include="*.rs" | wc -l
```

**修复规则**:
```rust
// ❌ 错误：只覆盖了 macOS，Linux/Windows 无对应分支
#[cfg(target_os = "macos")]
{
    networks = Self::macos_scan(interface);
}
// Linux/Windows 编译: networks 未初始化 → error

// ✅ 正确：至少有一个默认/fallback 分支
#[cfg(target_os = "macos")]
{ networks = Self::macos_scan(interface); }
#[cfg(target_os = "linux")]
{ networks = Self::linux_scan(interface); }
#[cfg(target_os = "windows")]
{ networks = Self::windows_scan(interface); }
// 或者: 先初始化默认值，再按平台覆盖
let mut networks = Vec::new();
#[cfg(target_os = "macos")]
{ networks = Self::macos_scan(interface); }
```

---

### 阶段 3: 工具实现完整性检查

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

### 阶段 4: 前后端接口一致性检查

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

### 阶段 5: 代码质量与模式一致性检查

**目标**: 发现代码异味、不一致模式、Svelte 迁移残留。

#### 5.1 Rust 端检查

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
   - 检查每个工具的历史管理命令是否为复制粘贴？
   - 检查 `others/mod.rs` 和 `lib.rs` 中是否重复导出相同类型？

4. **异步模式一致性**: 是否所有 I/O 操作都在 tokio 上下文中执行？

#### 5.2 Svelte 前端检查

**检查项**:
1. **Svelte 4/5 混合模式**:
   ```bash
   grep -rn '\$:' src/ --include="*.svelte"
   grep -rn 'export let' src/ --include="*.svelte"
   grep -rn '\$state\|\$derived\|\$effect\|\$props' src/ --include="*.svelte"
   ```

2. **未使用的导入和代码**:
   ```bash
   npx svelte-check --tsconfig ./tsconfig.json 2>&1 | grep -i "unused\|never read"
   ```

3. **重复模式检测**: 确认对话框、导出下拉菜单、分页逻辑是否重复？

---

### 阶段 6: 架构债务评估

**目标**: 识别架构层面的技术债务。

#### 6.1 数据流完整性

| 组件 | 预期状态 | 实际状态 | 差距 |
|------|----------|----------|------|
| `core/engine/EventBus` | 被 Tauri 层使用 | 仅在 core 库中，Tauri 未集成 | 🔴 完全未使用 |
| `core/engine/Correlator` | 事件关联分析 | 同上 | 🔴 完全未使用 |
| `core/engine/ScanOrchestrator` | 编排复杂扫描 | 同上 | 🔴 完全未使用 |
| `plugins/` 插件系统 | 可扩展工具注册 | 空模块 | 🔴 完全未实现 |
| `lib/core/events.ts` | 前端事件总线 | EventBus 类已定义但无引用 | 🟡 未使用 |
| 全局状态管理 | 共享 AppState Store | 无 | 🟡 未实现 |
| 工具注册表 (ToolRegistry) | 动态工具发现 | 仅注册 2 个工具 | 🟡 未充分利用 |

#### 6.2 安全性检查

```bash
# 敏感信息硬编码
grep -rn "password\|api_key\|secret\|token\|credential" crates/ src-tauri/ --include="*.rs" | grep -v "struct\|enum\|fn\|let mut\|//\|///"

# 不安全的 Rust 代码
grep -rn "unsafe" crates/ src-tauri/ --include="*.rs"

# 依赖安全性
cargo audit
```

#### 6.3 性能痛点

1. **同步阻塞 I/O**: 是否在 async 上下文中调用阻塞函数？
2. **大文件**: `exploit_framework/config.rs` (66KB), `cloud_audit/config.rs` (1374行) — 是否应该拆分？

---

### 阶段 7: 自动修复与优化

**目标**: 对前 6 个阶段发现的问题进行自动修复。

#### 修复优先级矩阵（含跨平台修复）

| 优先级 | 问题类型 | 修复策略 | 来源阶段 |
|--------|----------|----------|----------|
| **P0** | 编译错误（任何平台） | 立即修复 | 阶段1 |
| **P0** | `cargo clippy -W warnings` error | 立即修复（CI 等效检查） | 阶段1 |
| **P0** | OS 专有 API 缺少 cfg 守卫/trait 导入 | 添加 `#[cfg]` 守卫 + `use` 导入 | 阶段2 |
| **P0** | Regex look-around 不兼容 | 替换为兼容的正则模式 | 阶段2 |
| **P0** | 构建工具配置不一致 | 统一为项目使用的包管理器 | 阶段2 |
| **P0** | 跨平台未使用变量/导入 | 添加 `#[cfg_attr]` 守卫 | 阶段2 |
| **P1** | `.unwrap()` 在生产路径 | 替换为 `?` | 阶段5 |
| **P1** | Stub 工具有 Tauri 命令但无实现 | 添加错误处理 | 阶段3 |
| **P1** | 前端调用不存在的命令 | 移除调用或注册命令 | 阶段4 |
| **P1** | 硬编码敏感信息 | 替换为环境变量 | 阶段6 |
| **P2** | Svelte 4→5 迁移 | 逐文件迁移（分批） | 阶段5 |
| **P2** | 重复代码抽象 | 抽取共享组件/函数 | 阶段5 |
| **P2** | 未使用的导入 | 自动移除 | 阶段5 |
| **P3** | 死代码 | 标记，下轮清理 | 阶段5 |
| **P3** | 样式统一 | Tailwind vs scoped CSS 决策 | 阶段5 |

#### 跨平台修复检查清单（每次修复后必做）

修改涉及以下任一情况时，必须额外验证：
1. **涉及 OS API**: 确认 `#[cfg]` 守卫 + trait 导入完整
2. **涉及 Regex**: 确认无不兼容的 look-around 语法
3. **涉及 cfg 分支**: 确认所有目标平台都有对应的代码路径
4. **涉及函数签名修改**: 确认不会导致某平台上的 unused_variables

**每次修复后的验证命令**:
```bash
# 基础编译
cargo check --workspace

# CI 严格模式（关键！）
cargo clippy --workspace -- -W warnings
```

---

### 阶段 8: Git 提交与推送

**目标**: 将本次巡检发现并修复的所有变更，提交并推送到 GitHub。

> 此阶段与 2.0 版本相同，保持不变。

**前置条件**:
- 阶段 1~7 已完成
- `cargo clippy --workspace -- -W warnings` 通过（0 errors）

**执行步骤**:

#### 8.1 检查当前 Git 状态

```bash
cd /Users/liwenchao/GithubProSpace/biosphere-network-app
git status
git diff --stat
```

- 如果 `nothing to commit` → 无需提交，记录到报告
- 如果有未暂存的变更 → 进入 8.2

#### 8.2 审查变更内容

```bash
git diff --name-only
git diff --cached --name-only
git diff --stat
git diff --cached --stat
```

**审查清单**:
1. [ ] 只修改了源代码文件（`.rs`, `.svelte`, `.ts`, `.json`, `.toml`, `.md`）？
2. [ ] 未误修改构建产物（`target/`, `build/`, `node_modules/`）？
3. [ ] 未误修改敏感文件（`.env`, `*.db`）？
4. [ ] 变更行数是否合理（通常 < 500 行）？
5. [ ] **跨平台编译检查**: `cargo clippy --workspace -- -W warnings` 是否通过？

#### 8.3 暂存并提交

```bash
git add -A
git reset -- target/ build/ node_modules/ .svelte-kit/
git diff --cached --stat
```

**Commit 消息格式**:

```
chore(巡检): YYYY-MM-DD 自动化代码质量巡检 — [主要动作]

## 编译修复
- [具体修复项]

## 跨平台兼容性
- [具体修复项]

## 代码质量
- [具体修复项]

## 工具完整性
- [具体修复项]

## 前后端一致性
- [具体修复项]

跨平台验证: cargo clippy --workspace -- -W warnings ✅
巡检报告: docs/AUTOMATION_PROMPT.md
健康度评分: XXX/10
```

**重要规则**:
- 使用 `chore(巡检):` 前缀
- 消息中包含日期和跨平台验证状态
- 列出关键修复项
- 无变更则标记 `NO_CHANGES`

#### 8.4 推送到 GitHub

```bash
git push origin main
```

**推送前检查**:
```bash
git branch --show-current              # 确认在 main 分支
git fetch origin
git log HEAD..origin/main --oneline    # 检查远程更新
```
如果有远程新提交，先 `git pull --rebase origin main`。

**推送后验证**:
```bash
git log --oneline -3
```

#### 8.5 推送失败处理

如果推送失败：
1. 记录错误日志到 `.workbuddy/memory/YYYY-MM-DD.md`
2. 在巡检报告中标记 `⚠️ Git 推送失败`
3. 最多重试 2 次
4. 本地 commit 保留，等待下次推送

---

## 输出格式

### 阶段报告模板

```markdown
## 阶段 N: [阶段名称] — [PASS / FAIL / WARN]

### 发现问题
| ID | 文件 | 行号 | 问题描述 | 严重度 | 状态 |
|----|------|------|----------|--------|------|
| N-1 | xxx.rs | 123 | xxx | P1 | ✅ 已修复 |
| N-2 | xxx.svelte | 45 | xxx | P2 | 📋 待处理 |

### 自动修复
- [修复内容]

### 跨平台验证（阶段2 专用）
| 平台 | 状态 | 备注 |
|------|------|------|
| macOS | ✅ | - |
| Linux | ✅ | - |
| Windows | ✅ | - |

### 遗留项
- [需要人工判断的事项]
```

### 最终汇总报告

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
| 编译状态 (cargo check) | ✅ / ❌ |
| CI 严格模式 (clippy -W warnings) | ✅ / ❌ |
| 跨平台兼容性 | ✅ / ❌ |
| 前端检查 | ✅ / ❌ |
| Git 提交 | ✅ 已推送 / ⚠️ 无变更 / ❌ 推送失败 |
| Commit SHA | abc1234 |

## 关键发现
1. [最重要的发现]

## 健康度评分
| 维度 | 评分 | 说明 |
|------|------|------|
| 编译健康度 | X/10 | |
| **跨平台兼容性** | X/10 | 新增维度 |
| 代码完整性 | X/10 | |
| 前后端一致性 | X/10 | |
| 架构债务 | X/10 | |
| **综合评分** | **X/10** | |

## 下一次巡检建议
- [建议关注的点]
```

---

## 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `AUTO_FIX` | `true` | 是否自动修复 P0/P1 问题 |
| `MAX_FIX_ATTEMPTS` | `3` | 编译错误最大修复尝试次数 |
| `SKIP_STUBS` | `false` | 是否跳过 stub 工具检查 |
| `REPORT_ONLY` | `false` | 仅生成报告，不做任何修改 |
| `AUTO_COMMIT` | `true` | 是否自动提交并推送变更到 GitHub |
| `CROSS_PLATFORM_CHECK` | `true` | **新增**: 是否执行跨平台兼容性验证 |
| `CLIPPY_STRICT` | `true` | **新增**: 是否执行 `cargo clippy -- -W warnings` |
| `COMMIT_PREFIX` | `chore(巡检):` | Git commit 消息前缀 |
| `TARGET_BRANCH` | `main` | 推送目标分支 |

---

## 变更记录

| 版本 | 日期 | 变更内容 |
|------|------|----------|
| 3.0 | 2026-05-21 | **重大升级**: 新增阶段2跨平台兼容性验证；阶段1升级为 CI 等效检查（clippy -W warnings）；新增 regex 兼容性、OS API 守卫、构建工具一致性、cfg 分支完整性 4 项专项检查；修复优先级矩阵新增跨平台 P0 项；新增健康度评分维度"跨平台兼容性" |
| 2.0 | 2026-05-21 | 新增阶段7 Git提交与推送；升级为 7 阶段流程 |
| 1.0 | 2026-05-21 | 初始版本（6 阶段） |

---

*此提示词设计用于 WorkBuddy 自动化定时执行，建议每周执行一次。*

# Biosphere Network App - 项目命令指南

本文档总结了 Biosphere Network App 项目的启动、编译和开发命令。

## 📋 目录

- [开发环境](#开发环境)
- [启动项目](#启动项目)
- [编译项目](#编译项目)
- [其他命令](#其他命令)
- [项目结构](#项目结构)
- [常见问题](#常见问题)

---

## 🛠️ 开发环境

### 前置要求

- **Node.js**: >= 18.0.0
- **Rust**: >= 1.70.0
- **操作系统**: macOS / Linux / Windows

### 安装依赖

```bash
# 进入项目目录
cd /Users/liwenchao/BiosPherePro/biosphere/biosphere-network-app

# 安装前端依赖
npm install

# Rust 依赖会在首次构建时自动安装
```

---

## 🚀 启动项目

### 1. 开发模式（推荐）

**启动开发服务器（仅前端）：**
```bash
npm run dev
```
- 📍 访问地址: `http://localhost:5173`
- ⚡ 热重载支持
- 🎨 实时预览更改
- ⚠️ 无后端功能

**启动 Tauri 开发模式（完整应用）：**
```bash
npm run tauri:dev
```
- 🖥️ 启动桌面应用
- 🔄 前端热重载
- ⚡ Rust 后端实时编译
- 🎯 完整功能测试
- 📦 自动打开应用窗口

### 2. 生产模式预览

**构建并预览前端：**
```bash
# 先构建
npm run build

# 预览构建结果
npm run preview
```
- 📍 访问地址: `http://localhost:4173`
- 🎨 生产环境预览
- ⚠️ 无后端功能

---

## 🏗️ 编译项目

### 1. 前端构建

**构建前端资源：**
```bash
npm run build
```
- 📦 输出目录: `build/`
- ⚡ 优化压缩
- 🎯 静态资源生成
- ⏱️ 构建时间: ~5-7秒

### 2. 完整应用构建

**构建桌面应用：**
```bash
npm run tauri build
```
- 📦 输出目录: `../target/release/bundle/`
- 🖥️ 生成可执行文件
- 📱 支持多平台:
  - **macOS**: `.app` 和 `.dmg`
  - **Linux**: `.deb` 和 `.AppImage`
  - **Windows**: `.exe` 和 `.msi`
- ⏱️ 构建时间: ~1-3分钟

**构建输出示例（macOS）：**
```
../target/release/bundle/
├── macos/
│   └── biosphere-network-app.app
└── dmg/
    └── biosphere-network-app_0.1.0_aarch64.dmg
```

---

## 🔧 其他命令

### 类型检查

**运行 TypeScript 类型检查：**
```bash
npm run check
```
- ✅ 检查类型错误
- 🔍 静态分析
- 📝 生成类型定义

### Tauri CLI

**直接使用 Tauri CLI：**
```bash
# 查看帮助
npm run tauri -- --help

# 开发模式
npm run tauri dev

# 构建
npm run tauri build

# 其他命令
npm run tauri -- [command]
```

---

## 📁 项目结构

```
biosphere-network-app/
├── src/                    # 前端源代码
│   ├── lib/               # 库文件
│   │   ├── i18n/         # 国际化
│   │   └── stores/       # 状态管理
│   ├── routes/           # 页面路由
│   │   ├── tools/        # 工具页面
│   │   │   ├── port_scanner/
│   │   │   ├── dns_query/
│   │   │   ├── ping/
│   │   │   └── target_manager/
│   │   └── history/      # 历史记录
│   └── app.html          # HTML 模板
├── src-tauri/             # Rust 后端代码
│   ├── src/              # Rust 源代码
│   ├── Cargo.toml        # Rust 配置
│   └── tauri.conf.json   # Tauri 配置
├── static/                # 静态资源
├── docs/                  # 文档
├── package.json           # NPM 配置
├── vite.config.ts         # Vite 配置
├── svelte.config.js       # Svelte 配置
└── tailwind.config.js     # Tailwind 配置
```

---

## ❓ 常见问题

### 1. 开发模式启动失败

**问题**: `npm run tauri:dev` 失败

**解决方案**:
```bash
# 检查 Rust 环境
rustc --version
cargo --version

# 清理并重新构建
rm -rf node_modules
npm install
cargo clean
npm run tauri:dev
```

### 2. 构建失败

**问题**: `npm run tauri build` 失败

**解决方案**:
```bash
# 更新 Rust
rustup update

# 清理构建缓存
cargo clean
npm run build
npm run tauri build
```

### 3. 端口被占用

**问题**: 端口 5173 或 4173 被占用

**解决方案**:
```bash
# macOS/Linux
lsof -ti:5173 | xargs kill -9
lsof -ti:4173 | xargs kill -9

# 或使用其他端口
npm run dev -- --port 5174
```

### 4. 依赖问题

**问题**: 依赖安装失败

**解决方案**:
```bash
# 清理缓存
npm cache clean --force
rm -rf node_modules package-lock.json
npm install

# 或使用 yarn
yarn install
```

---

## 🎯 快速参考

### 开发流程

```bash
# 1. 首次运行
npm install
npm run tauri:dev

# 2. 日常开发
npm run tauri:dev          # 启动开发模式

# 3. 构建发布
npm run tauri build        # 构建生产版本
```

### 仅前端开发

```bash
npm run dev                # 启动前端开发服务器
npm run build              # 构建前端
npm run preview            # 预览构建结果
```

### 仅后端开发

```bash
cd src-tauri
cargo build                # 构建 Rust 后端
cargo run                  # 运行 Rust 后端
```

---

## 📝 命令速查表

| 命令 | 说明 | 使用场景 |
|------|------|----------|
| `npm run dev` | 启动前端开发服务器 | 仅前端开发 |
| `npm run tauri:dev` | 启动完整开发环境 | 推荐：完整开发 |
| `npm run build` | 构建前端 | 前端构建 |
| `npm run tauri build` | 构建桌面应用 | 生产发布 |
| `npm run preview` | 预览构建结果 | 构建验证 |
| `npm run check` | 类型检查 | 代码检查 |

---

## 🔗 相关链接

- [Tauri 官方文档](https://tauri.app/v2/guide/)
- [SvelteKit 文档](https://kit.svelte.dev/docs)
- [Vite 文档](https://vitejs.dev/guide/)
- [Tailwind CSS 文档](https://tailwindcss.com/docs)

---

## 📅 更新日志

- **2024-01-XX**: 创建文档
- **2024-01-XX**: 添加常见问题解答
- **2024-01-XX**: 添加项目结构说明

---

## 👥 贡献者

如果您在使用过程中遇到问题或有改进建议，请提交 Issue 或 Pull Request。

---

**最后更新**: 2024年
**文档版本**: 1.0.0

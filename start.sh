#!/bin/bash

export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR"

LOG_DIR="$PROJECT_DIR/logs"
LOG_FILE="$LOG_DIR/biosphere-app.log"

log_info() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]${NC} $1"
}

log_usage() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [USAGE]${NC} $1"
}

check_rust() {
    if ! command -v cargo &> /dev/null; then
        log_error "Rust/Cargo 未安装或不在PATH中"
        exit 1
    fi
}

check_node() {
    if ! command -v node &> /dev/null; then
        log_error "Node.js 未安装或不在PATH中"
        exit 1
    fi
    if ! command -v npm &> /dev/null; then
        log_error "npm 未安装或不在PATH中"
        exit 1
    fi
}

create_directories() {
    mkdir -p "$LOG_DIR"
}

build_rust_lib() {
    log_info "正在构建 Rust workspace..."
    cd "$APP_DIR"
    cargo build
    if [ $? -ne 0 ]; then
        log_error "Rust workspace 构建失败"
        exit 1
    fi
    log_info "Rust workspace 构建成功"
}

install_node_deps() {
    log_info "正在检查 Node 依赖..."
    cd "$APP_DIR"
    if [ ! -d "node_modules" ]; then
        log_info "安装 Node 依赖..."
        npm install
        if [ $? -ne 0 ]; then
            log_error "Node 依赖安装失败"
            exit 1
        fi
        log_info "Node 依赖安装成功"
    else
        log_info "Node 依赖已存在"
    fi
}

pre_check() {
    check_rust
    check_node
    create_directories
}

show_help() {
    echo "Biosphere Network App 管理脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  dev              开发模式启动（Tauri 开发服务器，默认）"
    echo "  build            构建应用"
    echo "  build:lib        仅构建 Rust 核心库"
    echo "  clean            清理构建文件"
    echo "  check            检查开发环境"
    echo "  check:frontend   前端类型检查 (svelte-check)"
    echo "  install          安装依赖"
    echo "  help, -h, --help 显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0               # 开发模式启动"
    echo "  $0 dev           # 开发模式启动"
    echo "  $0 build         # 构建应用"
    echo "  $0 clean         # 清理构建文件"
    echo "  $0 check         # 检查环境"
}

start_dev() {
    log_info "Biosphere Network App 开发模式启动"
    echo "========================================"
    pre_check
    install_node_deps
    log_info "正在启动 Tauri 开发服务器..."
    cd "$APP_DIR"
    npm run tauri:dev
}

build_app() {
    log_info "Biosphere Network App 构建"
    echo "========================================"
    pre_check
    install_node_deps
    build_rust_lib
    log_info "正在构建应用..."
    cd "$APP_DIR"
    npm run tauri build
    if [ $? -ne 0 ]; then
        log_error "应用构建失败"
        exit 1
    fi
    log_info "应用构建成功"
}

build_lib_only() {
    log_info "仅构建 Rust 核心库"
    echo "========================================"
    check_rust
    build_rust_lib
}

clean_project() {
    log_info "清理构建文件..."
    cd "$APP_DIR"
    rm -rf node_modules
    rm -rf .svelte-kit
    rm -rf build
    rm -rf target
    log_info "清理完成"
}

check_environment() {
    log_info "检查开发环境..."
    echo "========================================"
    if command -v rustc &> /dev/null; then
        log_info "Rust 版本: $(rustc --version)"
    else
        log_error "Rust 未安装"
    fi
    if command -v cargo &> /dev/null; then
        log_info "Cargo 版本: $(cargo --version)"
    else
        log_error "Cargo 未安装"
    fi
    if command -v node &> /dev/null; then
        log_info "Node.js 版本: $(node --version)"
    else
        log_error "Node.js 未安装"
    fi
    if command -v npm &> /dev/null; then
        log_info "npm 版本: $(npm --version)"
    else
        log_error "npm 未安装"
    fi
    cd "$APP_DIR"
    if [ -f "package.json" ]; then
        log_info "package.json: OK"
    else
        log_error "package.json 缺失"
    fi
    if [ -f "src-tauri/tauri.conf.json" ]; then
        log_info "Tauri 配置: OK"
    else
        log_error "Tauri 配置缺失"
    fi
    if [ -f "Cargo.toml" ]; then
        log_info "Workspace Cargo.toml: OK"
    else
        log_error "Workspace Cargo.toml 缺失"
    fi
    echo ""
    log_info "环境检查完成"
}

check_frontend() {
    log_info "前端类型检查 (svelte-check)..."
    echo "========================================"
    cd "$APP_DIR"
    npm run check
    if [ $? -ne 0 ]; then
        log_warn "svelte-check 发现一些问题，请查看上方输出"
    else
        log_info "svelte-check 通过"
    fi
}

install_deps() {
    log_info "安装所有依赖..."
    echo "========================================"
    check_node
    cd "$APP_DIR"
    rm -rf node_modules
    npm install
    if [ $? -ne 0 ]; then
        log_error "依赖安装失败"
        exit 1
    fi
    log_info "依赖安装成功"
}

main() {
    case "$1" in
        dev|"")
            start_dev
            ;;
        build)
            build_app
            ;;
        build:lib)
            build_lib_only
            ;;
        clean)
            clean_project
            ;;
        check)
            check_environment
            ;;
        check:frontend)
            check_frontend
            ;;
        install)
            install_deps
            ;;
        help|-h|--help)
            show_help
            ;;
        *)
            log_error "未知选项: $1"
            log_usage "使用 '$0 help' 查看帮助信息"
            exit 1
            ;;
    esac
}

main "$@"

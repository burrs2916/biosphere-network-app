use biosphere_network::{ToolRegistry, ToolArgs, PortScanner, HostToIp};

fn main() {
    let mut registry = ToolRegistry::new();
    registry.register(PortScanner::new());
    registry.register(HostToIp::new());

    println!("=== 示例 1: Host to IP ===");
    let args = ToolArgs::new(Some("localhost".to_string()));
    match registry.run_tool("host_to_ip", args, None) {
        Ok(output) => {
            if output.success {
                println!("✅ 解析成功:");
                println!("{}", output.data);
            } else {
                println!("❌ 解析失败: {:?}", output.error);
            }
        }
        Err(e) => println!("❌ 错误: {}", e),
    }

    println!("\n=== 示例 2: Port Scanner ===");
    let args = ToolArgs::new(Some("127.0.0.1".to_string()))
        .with_option("scan_mode".to_string(), "quick".to_string())
        .with_option("timeout_ms".to_string(), "500".to_string());

    match registry.run_tool("port_scanner", args, None) {
        Ok(output) => {
            if output.success {
                println!("✅ 扫描成功:");
                println!("{}", output.data);
            } else {
                println!("❌ 扫描失败: {:?}", output.error);
            }
        }
        Err(e) => println!("❌ 错误: {}", e),
    }

    println!("\n=== 示例 3: 列出所有工具 ===");
    let tools = registry.list_tools();
    for tool in tools {
        println!("- {} ({})", tool.name, tool.id);
        println!("  描述: {}", tool.description);
    }
}

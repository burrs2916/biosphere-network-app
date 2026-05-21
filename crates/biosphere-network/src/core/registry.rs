use std::collections::HashMap;

use super::error::{Result, ToolError};
use super::progress::ProgressReporter;
use super::tool::{Tool, ToolArgs, ToolInfo, ToolOutput};

pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register<T: Tool + 'static>(&mut self, tool: T) {
        let info = tool.info();
        self.tools.insert(info.id, Box::new(tool));
    }

    pub fn list_tools(&self) -> Vec<ToolInfo> {
        self.tools.values().map(|t| t.info()).collect()
    }

    pub fn get_tool(&self, id: &str) -> Option<&dyn Tool> {
        self.tools.get(id).map(|t| t.as_ref())
    }

    pub fn run_tool(
        &self,
        id: &str,
        args: ToolArgs,
        progress: Option<Box<dyn ProgressReporter>>,
    ) -> Result<ToolOutput> {
        let tool = self
            .tools
            .get(id)
            .ok_or_else(|| ToolError::NotFoundError(id.to_string()))?;
        tool.run(args, progress)
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

# 目标管理系统功能说明

## 概述

目标管理系统是 BiosPhere Network 应用的核心模块，用于管理和维护网络扫描目标。该系统提供了基础的CRUD操作，并与端口扫描、Ping、DNS查询等工具进行了集成。

## 已实现功能

### 1. 数据模型

#### Target（目标）模型
已定义以下字段：

**基础字段（已在UI中显示和使用）：**
- `id`: 唯一标识符
- `name`: 目标名称
- `target_type`: 目标类型（IP、Domain、URL、Subnet、Range）
- `target_value`: 目标值
- `description`: 描述信息
- `tags`: 标签（逗号分隔）
- `location`: 地理位置
- `organization`: 所属组织
- `created_at`: 创建时间
- `updated_at`: 更新时间
- `last_scanned_at`: 最后扫描时间
- `is_active`: 是否激活

**扩展字段（已定义但未在UI中使用）：**
- `group_id`: 分组ID
- `status`: 状态（new, active, inactive, archived）
- `risk_level`: 风险等级（none, low, medium, high, critical）
- `priority`: 优先级（low, normal, high, critical）
- `owner`: 所有者
- `contact`: 联系人
- `auto_scan`: 是否自动扫描
- `scan_interval`: 扫描间隔（秒）
- `next_scan_at`: 下次扫描时间
- `total_scans`: 总扫描次数
- `open_ports_count`: 开放端口数
- `vulnerabilities_count`: 漏洞数量
- `metadata`: 元数据（JSON格式）

#### TargetGroup（目标分组）模型
已定义以下字段（后端API已实现，UI未实现）：

**基础字段：**
- `id`: 唯一标识符
- `name`: 分组名称
- `description`: 描述信息
- `parent_id`: 父分组ID（支持层级结构）
- `created_at`: 创建时间
- `updated_at`: 更新时间

**扩展字段：**
- `color`: 分组颜色
- `icon`: 分组图标
- `is_shared`: 是否共享
- `auto_scan`: 是否自动扫描
- `scan_interval`: 扫描间隔
- `next_scan_at`: 下次扫描时间
- `total_targets`: 目标总数
- `active_targets`: 活跃目标数

### 2. 数据库功能

#### 数据库迁移
- 实现了从v3到v4的数据库迁移
- 支持平滑升级，保留历史数据
- 自动创建新表和字段

#### CRUD操作
**Target操作：**
- `create_target`: 创建目标
- `update_target`: 更新目标
- `get_targets`: 获取目标列表（支持分页）
- `get_target_by_value`: 根据目标值查询
- `delete_target`: 删除目标
- `search_targets`: 搜索目标

**TargetGroup操作：**
- `create_target_group`: 创建分组
- `update_target_group`: 更新分组
- `get_target_groups`: 获取分组列表
- `delete_target_group`: 删除分组

### 3. 用户界面

#### 目标管理页面
**已实现：**
- 目标列表展示（表格形式）
- 目标搜索功能
- 创建目标弹窗
- 编辑目标弹窗
- 删除目标确认
- 分页功能
- 标签展示（只读）

**显示字段：**
- 目标名称
- 目标类型
- 目标值
- 标签
- 所属组织
- 最后扫描时间
- 操作按钮（编辑、删除）

**未显示字段：**
- 状态、风险等级、优先级等扩展字段
- 分组信息
- 扫描统计信息

#### 工具集成
**端口扫描工具：**
- 添加"选择目标"按钮
- 支持从目标管理中选择目标
- 支持多选
- 支持搜索过滤

**Ping工具：**
- 添加"选择目标"按钮
- 支持从目标管理中选择目标
- 支持多选
- 支持搜索过滤

**DNS查询工具：**
- 添加"选择目标"按钮
- 支持从目标管理中选择目标
- 支持多选
- 支持搜索过滤

### 4. 国际化支持

支持中英文双语：
- 目标管理页面所有文本
- 目标选择器界面
- 错误提示信息
- 表单标签和提示

## 部分实现功能

### 1. 标签系统
- **已实现：** 标签存储、解析、显示
- **未实现：** 标签管理界面、标签筛选、标签统计

### 2. 目标分组
- **已实现：** 后端API、数据模型
- **未实现：** UI界面、分组选择器、分组管理

### 3. 目标状态管理
- **已实现：** 数据模型定义
- **未实现：** UI显示、状态更新逻辑、状态历史

## 未实现功能

### 1. 自动扫描
- 定时扫描调度
- 扫描任务队列
- 扫描结果自动更新

### 2. 统计分析
- 目标扫描统计
- 开放端口统计
- 漏洞统计
- 趋势分析

### 3. 风险评估
- 风险等级计算
- 风险报告生成
- 风险趋势分析

### 4. 扫描历史关联
- 扫描历史与目标关联
- 历史记录查询
- 结果对比分析

### 5. 高级功能
- 目标导入导出（批量）
- 目标验证（连通性测试）
- 目标去重
- 目标批量编辑
- 目标标签批量管理

## 技术架构

### 前端
- **框架：** Svelte + TypeScript
- **UI组件：** 自定义组件，统一暗色主题
- **国际化：** 自定义i18n模块
- **状态管理：** Svelte响应式变量

### 后端
- **框架：** Tauri (Rust)
- **数据库：** SQLite
- **ORM：** 手写SQL查询
- **API：** Tauri Command

### 数据流
```
前端UI → Tauri Invoke → Rust Command → Database Repository → SQLite
```

## 数据库表结构

### targets表
```sql
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL UNIQUE,
    description TEXT,
    tags TEXT,
    location TEXT,
    organization TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_scanned_at TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    
    -- 扩展字段
    group_id INTEGER,
    status TEXT NOT NULL DEFAULT 'new',
    risk_level TEXT NOT NULL DEFAULT 'none',
    priority TEXT NOT NULL DEFAULT 'normal',
    owner TEXT,
    contact TEXT,
    auto_scan INTEGER NOT NULL DEFAULT 0,
    scan_interval INTEGER,
    next_scan_at TEXT,
    total_scans INTEGER NOT NULL DEFAULT 0,
    open_ports_count INTEGER NOT NULL DEFAULT 0,
    vulnerabilities_count INTEGER NOT NULL DEFAULT 0,
    metadata TEXT,
    
    FOREIGN KEY (group_id) REFERENCES target_groups(id)
);
```

### target_groups表
```sql
CREATE TABLE target_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    parent_id INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    
    -- 扩展字段
    color TEXT,
    icon TEXT,
    is_shared INTEGER NOT NULL DEFAULT 0,
    auto_scan INTEGER NOT NULL DEFAULT 0,
    scan_interval INTEGER,
    next_scan_at TEXT,
    total_targets INTEGER NOT NULL DEFAULT 0,
    active_targets INTEGER NOT NULL DEFAULT 0,
    
    FOREIGN KEY (parent_id) REFERENCES target_groups(id)
);
```

## API接口

### target_manager命令
统一的Tauri命令，通过action参数区分操作：

**支持的action：**
- `list`: 获取目标列表
- `search`: 搜索目标
- `create`: 创建目标
- `update`: 更新目标
- `delete`: 删除目标
- `get_groups`: 获取分组列表

**示例调用：**
```typescript
// 获取目标列表
const result = await invoke('target_manager', {
  action: 'list',
  page: 1,
  pageSize: 10
});

// 创建目标
const result = await invoke('target_manager', {
  action: 'create',
  name: '目标名称',
  target_type: 'IP',
  target_value: '192.168.1.1',
  description: '描述信息',
  tags: 'tag1,tag2'
});
```

## 待优化项

### 性能优化
- 大量目标时的分页性能优化
- 搜索功能的索引优化
- 批量操作的性能优化

### 用户体验
- 添加加载状态提示
- 优化错误提示信息
- 添加操作确认提示
- 支持键盘快捷键

### 代码质量
- 添加单元测试
- 添加集成测试
- 代码注释完善
- 错误处理统一

## 总结

目标管理系统目前实现了基础的CRUD操作和工具集成功能，数据模型已经为未来扩展做好了准备。系统架构清晰，代码结构合理，为后续功能扩展奠定了良好的基础。

主要不足：
1. 扩展字段在UI中未充分利用
2. 目标分组功能缺少UI实现
3. 缺少自动化和统计分析功能
4. 部分高级功能尚未实现

建议优先实现：
1. 目标分组UI
2. 标签管理功能
3. 目标状态展示和更新
4. 扫描历史关联

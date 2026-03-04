# AstrBot 提示词守卫 (Prompt Guardian) v1.0.0 正式版

## 🚀 插件简介

**Prompt Guardian v1.0.0** (原 AntiPromptInjector) 是基于原版重构后的全新正式版本。本插件旨在为 AstrBot 提供强大的提示词安全防护，防止伪系统注入、越狱攻击及恶意诱导行为。

通过全新的模块化架构设计和增强的本地启发式检测引擎，v1.0.0 实现了更低的大模型依赖和更快的拦截响应速度。

### ✨ 核心特性

#### 1. 🛡️ 深度防御体系
- **本地启发式检测 (PTD Core v1.0)**：基于高权重正则特征库，无需联网即可毫秒级识别主流注入攻击（如 JSON 伪造、Role 伪装）。
- **智能 LLM 审计**：对本地检测存疑的复杂提示词，自动调用大模型进行二次语义分析（支持 standby/active 模式）。
- **即时阻断**：检测到高风险特征时直接拦截，确保恶意指令无法触达 LLM。

#### 2. ⚡ 高性能 WebUI
- **轻量化重构**：采用 `asyncio` 原生异步服务，完全剥离冗余依赖，资源占用极低。
- **可视化看板**：提供实时拦截统计、风险日志审计、黑白名单管理及在线配置修改。
- **安全加固**：支持 HMAC 签名锁定与输入清洗 (`sanitize`)，防止 WebUI 自身成为攻击面。

#### 3. 🧩 模块化架构
- 代码结构清晰，分为核心逻辑 (`main.py`)、检测引擎 (`ptd_core.py`)、WebUI 服务 (`webui_server.py`) 及资源文件 (`webui_resources.py`)，便于二次开发与维护。

### 🛠️ 安装与升级

1. **全新安装**：将插件目录放入 AstrBot 的 `plugins/` 文件夹，重启即可。
2. **从旧版升级**：
   - 建议删除旧版插件目录，重新部署 v1.0.0 版本。
   - 配置文件 `config.json` 结构兼容，插件会自动迁移旧配置。

### 📋 默认配置

```json
{
  "enabled": true,
  "defense_mode": "intercept",
  "sanitize_enabled": true,
  "webui_enabled": true,
  "webui_port": 18888
}
```

### 📝 版权信息
- **作者**: LumineStory
- **版本**: v1.0.0 (Refactored Release)

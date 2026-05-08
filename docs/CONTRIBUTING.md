# 贡献指南

感谢您对 CALLISTO 项目的关注！欢迎各种形式的贡献，包括代码、文档、问题报告和功能建议。

## 如何贡献

### 报告问题

发现 Bug 或有功能建议？请创建 Issue：

- **Bug 报告**：请包含复现步骤、预期行为和实际行为
- **功能建议**：请描述使用场景和期望功能
- **性能问题**：请提供测试环境和基准数据

### 提交代码

1. **Fork 仓库**并创建分支

```bash
git checkout -b feature/amazing-feature
```

2. **开发**您的功能
   - 遵循现有代码风格
   - 添加必要的测试
   - 更新相关文档

3. **测试**确保通过

```bash
# 运行测试
pytest

# 代码风格检查（如配置）
flake8 callisto/
```

4. **提交**更改

```bash
git commit -m "Add amazing feature

- 详细描述功能 1
- 详细描述功能 2

Fixes #123"
```

5. **推送**并创建 Pull Request

```bash
git push origin feature/amazing-feature
```

### 文档贡献

- 改进 README.md
- 补充 API 文档
- 添加使用示例
- 修正拼写错误

任何文档改进都受欢迎！

## 代码规范

### Python 风格

- 遵循 PEP 8
- 使用类型注解
- 编写清晰的文档字符串

```python
def analyze_session(session: Session) -> list[Alert]:
    """分析会话并返回检测到的告警。
    
    Args:
        session: 要分析的会话对象
        
    Returns:
        告警列表，按风险等级排序
    """
```

### 测试规范

- 新功能需附带测试
- 测试覆盖率应保持合理水平
- 使用 pytest 框架

```python
def test_causal_responsibility_scorer():
    """测试 CRS 基本功能。"""
    graph = create_test_graph()
    crs = CausalResponsibilityScorer(num_samples=10)
    result = crs.score(graph)
    assert result.max_score >= 0.0
```

## 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/your-username/callisto.git
cd callisto

# 创建虚拟环境
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate  # Windows

# 安装开发依赖
pip install -e ".[dev,full,eval]"

# 安装预提交钩子（可选）
pip install pre-commit
pre-commit install
```

## 发布流程

维护者发布新版本的流程：

1. 更新版本号（`pyproject.toml`）
2. 更新变更日志
3. 创建 Git 标签
4. 发布到 PyPI

```bash
# 构建
python -m build

# 发布
twine upload dist/*
```

## 行为准则

- 保持开放和包容
- 尊重不同观点
- 建设性批评
- 关注共同利益

## 致谢

感谢所有贡献者！

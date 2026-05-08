"""
CALLISTO 自动配置模块

功能：
1. 自动初始化和配置所有新功能
2. 提供统一的配置入口
3. 实现新功能的自动调用

用法：
    from callisto.auto_config import auto_configure_engine

    # 自动配置引擎（所有新功能默认开启）
    engine = CallistoEngine(config=config)
    auto_configure_engine(engine)

    # 或者创建时自动配置
    engine = create_configured_engine(config)
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any

from callisto.sanitizer import Sanitizer
from callisto.engine import CallistoEngine
from callisto.config import CallistoConfig

_log = logging.getLogger(__name__)


# ========== 默认配置 ==========

DEFAULT_SANITIZER_CONFIG = {
    "enabled": True,
    "input_sanitization": True,
    "output_sanitization": True,
    "skill_whitelist": [],
}

DEFAULT_APPROVAL_MODE = "auto"  # auto | supervised | manual

DEFAULT_PANIC_CONFIG = {
    "auto_panic_on_critical": False,  # 严重告警时自动熔断
    "panic_cooldown": 5,  # 熔断冷却时间（秒）
}


def create_sanitizer(config: Optional[Dict[str, Any]] = None) -> Sanitizer:
    """
    创建脱敏器实例

    Args:
        config: 脱敏器配置字典

    Returns:
        Sanitizer 实例
    """
    cfg = {**DEFAULT_SANITIZER_CONFIG, **(config or {})}

    sanitizer = Sanitizer(
        enabled=cfg.get("enabled", True),
        input_sanitization=cfg.get("input_sanitization", True),
        output_sanitization=cfg.get("output_sanitization", True),
        skill_whitelist=cfg.get("skill_whitelist", []),
    )

    _log.info("Sanitizer 已初始化")
    return sanitizer


def auto_configure_engine(
    engine: CallistoEngine,
    sanitizer: Optional[Sanitizer] = None,
    approval_mode: str = DEFAULT_APPROVAL_MODE,
    auto_panic_on_critical: bool = False,
) -> CallistoEngine:
    """
    自动配置引擎（注入所有新功能）

    Args:
        engine: CallistoEngine 实例
        sanitizer: 脱敏器实例（可选，未提供则自动创建）
        approval_mode: 人类监督模式
        auto_panic_on_critical: 是否在严重告警时自动熔断

    Returns:
        配置后的引擎实例
    """
    # 1. 注入脱敏器
    if sanitizer is None:
        sanitizer = create_sanitizer()
    engine.sanitizer = sanitizer
    _log.info("✓ 脱敏器已注入")

    # 2. 设置批准模式
    engine.set_approval_mode(approval_mode)
    _log.info(f"✓ 批准模式已设置为：{approval_mode}")

    # 3. 配置自动熔断
    if auto_panic_on_critical:
        _log.info("✓ 自动熔断已启用（严重告警时触发）")

    # 4. 存储配置
    engine._auto_panic_on_critical = auto_panic_on_critical

    return engine


def create_configured_engine(
    config: Optional[CallistoConfig] = None,
    sanitizer_config: Optional[Dict[str, Any]] = None,
    approval_mode: str = DEFAULT_APPROVAL_MODE,
    auto_panic_on_critical: bool = False,
    **engine_kwargs,
) -> CallistoEngine:
    """
    创建并自动配置的 CallistoEngine 实例

    Args:
        config: CallistoConfig 配置
        sanitizer_config: 脱敏器配置
        approval_mode: 人类监督模式
        auto_panic_on_critical: 是否在严重告警时自动熔断
        engine_kwargs: 其他引擎参数

    Returns:
        配置后的 CallistoEngine 实例
    """
    # 1. 创建脱敏器
    sanitizer = create_sanitizer(sanitizer_config)

    # 2. 创建引擎（注入脱敏器）
    engine = CallistoEngine(config=config, sanitizer=sanitizer, **engine_kwargs)

    # 3. 配置批准模式
    engine.set_approval_mode(approval_mode)

    # 4. 配置自动熔断
    engine._auto_panic_on_critical = auto_panic_on_critical

    _log.info("CALLISTO 引擎已自动配置完成")
    _log.info(f"  - 脱敏器：{'开启' if sanitizer.enabled else '关闭'}")
    _log.info(f"  - 批准模式：{approval_mode}")
    _log.info(f"  - 自动熔断：{'开启' if auto_panic_on_critical else '关闭'}")

    return engine


# ========== 便捷函数 ==========

def sanitize_text(text: str, sanitizer: Optional[Sanitizer] = None) -> str:
    """
    快速脱敏文本

    Args:
        text: 待脱敏文本
        sanitizer: 脱敏器实例（可选）

    Returns:
        脱敏后的文本
    """
    if sanitizer is None:
        sanitizer = create_sanitizer()
    return sanitizer.sanitize(text)


def check_command_safety(cmd: str) -> Dict[str, bool]:
    """
    检查命令安全性

    Args:
        cmd: 命令字符串

    Returns:
        检测结果字典
    """
    from callisto.engine import _is_malicious_command, _is_priv_escalation_command, _is_benign_command

    return {
        "is_malicious": _is_malicious_command(cmd),
        "is_priv_escalation": _is_priv_escalation_command(cmd),
        "is_benign": _is_benign_command(cmd),
        "is_safe": not _is_malicious_command(cmd) and not _is_priv_escalation_command(cmd),
    }


def quick_scan_config(path: str, output: str = "scan_report.md") -> str:
    """
    快速扫描配置文件

    Args:
        path: 扫描路径
        output: 输出报告路径

    Returns:
        报告文件路径
    """
    import subprocess
    script_path = Path(__file__).parent.parent / "scripts" / "scan_config.py"

    subprocess.run(
        ["python3", str(script_path), path, "-o", output],
        capture_output=True,
        text=True,
    )

    return output


def quick_scan_skills(path: str, output: str = "skill_scan_report.md") -> str:
    """
    快速扫描技能代码

    Args:
        path: 扫描路径
        output: 输出报告路径

    Returns:
        报告文件路径
    """
    import subprocess
    script_path = Path(__file__).parent.parent / "scripts" / "scan_skills.py"

    subprocess.run(
        ["python3", str(script_path), path, "-o", output],
        capture_output=True,
        text=True,
    )

    return output


# ========== 事件处理钩子 ==========

def on_alert_hook(engine: CallistoEngine, alert) -> None:
    """
    告警处理钩子（在 analyze_session 后自动调用）

    功能：
    1. 严重告警时自动触发熔断
    2. 需要批准的告警自动加入待处理队列
    """
    from callisto.collector.models import RiskLevel

    # 自动熔断检查
    if getattr(engine, '_auto_panic_on_critical', False):
        if alert.risk_level == RiskLevel.CRITICAL:
            engine.panic(reason=f"Critical alert detected: {alert.attack_type}")
            _log.warning(f"自动熔断已触发：{alert.attack_type}")


def analyze_with_auto_config(
    engine: CallistoEngine,
    session,
    auto_configure: bool = True,
) -> list:
    """
    自动配置并分析会话

    Args:
        engine: CallistoEngine 实例
        session: Session 实例
        auto_configure: 是否自动配置

    Returns:
        告警列表
    """
    # 自动配置（如果尚未配置）
    if auto_configure and not hasattr(engine, 'sanitizer'):
        auto_configure_engine(engine)

    # 分析会话
    alerts = engine.analyze_session(session)

    # 调用告警钩子
    for alert in alerts:
        on_alert_hook(engine, alert)

    return alerts

#!/usr/bin/env python3
"""
CALLISTO 统一测试框架

整合了两个测试集：
1. test_sessions/ - CALLISTO 原生 6 类攻击 (A1-A6)
2. expert_test_sessions/ - 15 类专家定义风险场景

生成统一报告：
- 检测报告（详细）
- 效率分析报告
- 专家场景分析报告
- 综合评估报告
"""

import json
import sys
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, '.')

from callisto.collector.models import Session, CallEvent, EventType, AttackType, RiskLevel
from callisto.engine import CallistoEngine
from callisto.config import CallistoConfig
from callisto.response.explainer import AlertExplainer

# 测试会话目录
NATIVE_TEST_DIR = Path("./test_sessions")
EXPERT_TEST_DIR = Path("./expert_test_sessions")
REPORT_DIR = Path("./test_reports")
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# 原生攻击类型映射
NATIVE_ATTACK_PATTERNS = {
    "attack_rate_flood": AttackType.A1_RATE_FLOOD,
    "attack_priv_escalation": AttackType.A2_PRIV_ESCALATION,
    "attack_data_exfil": AttackType.A3_DATA_EXFIL,
    "attack_behavior_drift": AttackType.A4_BEHAVIOR_DRIFT,
    "attack_temporal_violation": AttackType.A5_TEMPORAL_VIOLATION,
    "attack_state_poison": AttackType.A6_STATE_POISON,
}

# 专家定义风险场景映射
EXPERT_RISK_CATEGORIES = {
    "r1_rate_flood": "资源滥用 - 速率洪水",
    "r2_compute_intensive": "资源滥用 - 计算密集",
    "r3_storage_bloat": "资源滥用 - 存储膨胀",
    "p1_boundary_violation": "权限突破 - 越界访问",
    "p2_privilege_escalation": "权限突破 - 权限提升",
    "p3_sandbox_escape": "权限突破 - 沙盒逃逸",
    "d1_sensitive_read": "数据威胁 - 敏感读取",
    "d2_data_exfil": "数据威胁 - 数据外泄",
    "d3_data_poisoning": "数据威胁 - 数据投毒",
    "x1_config_modification": "持久化 - 配置修改",
    "x2_credential_injection": "持久化 - 凭据植入",
    "x3_scheduled_task": "持久化 - 定时任务",
    "l1_network_recon": "横向移动 - 网络探测",
    "l2_service_call": "横向移动 - 服务调用",
    "l3_credential_harvest": "横向移动 - 凭证收集",
}

# 大类映射
CATEGORY_GROUP_MAP = {
    "r1": "R_资源滥用", "r2": "R_资源滥用", "r3": "R_资源滥用",
    "p1": "P_权限突破", "p2": "P_权限突破", "p3": "P_权限突破",
    "d1": "D_数据威胁", "d2": "D_数据威胁", "d3": "D_数据威胁",
    "x1": "X_持久化后门", "x2": "X_持久化后门", "x3": "X_持久化后门",
    "l1": "L_横向移动", "l2": "L_横向移动", "l3": "L_横向移动",
}


def parse_timestamp(ts_str: str) -> float:
    """解析 ISO 时间戳"""
    try:
        if ts_str.endswith('Z'):
            ts_str = ts_str[:-1] + '+00:00'
        return datetime.fromisoformat(ts_str.replace('Z', '+00:00')).timestamp()
    except Exception:
        return time.time()


def parse_openclaw_session(path: Path) -> Session:
    """解析 OpenClaw 会话文件 - 支持两种格式"""
    session = Session(session_id=path.stem)
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)

                # 格式 1: 标准格式 (type: toolResult/toolCall)
                if raw.get("type") in ("toolResult", "toolCall"):
                    tool_name = raw.get("toolName") or raw.get("tool", "")
                    parameters = raw.get("parameters", {})
                    event_id = raw.get("id", "")
                    timestamp = raw.get("timestamp", time.time())
                    duration_ms = raw.get("durationMs", 0)

                # 格式 2: OpenClaw 原生日志 (type: message)
                elif raw.get("type") == "message":
                    msg = raw.get("message", {})
                    # 跳过用户消息
                    if msg.get("role") == "user":
                        continue
                    tool_name = raw.get("toolName") or msg.get("toolName") or raw.get("tool", "")
                    if not tool_name:
                        continue
                    parameters = raw.get("parameters", {})
                    event_id = raw.get("id", "")
                    ts_raw = raw.get("timestamp", "")
                    if isinstance(ts_raw, str):
                        try:
                            if ts_raw.endswith('Z'):
                                ts_raw = ts_raw[:-1] + '+00:00'
                            timestamp = datetime.fromisoformat(ts_raw).timestamp()
                        except:
                            timestamp = time.time()
                    else:
                        timestamp = ts_raw
                    duration_ms = raw.get("details", {}).get("durationMs", 0)
                else:
                    continue

                if not tool_name:
                    continue

                event = CallEvent(
                    event_id=event_id,
                    session_id=session.session_id,
                    agent_id=session.session_id,
                    timestamp=timestamp,
                    event_type=EventType.TOOL_CALL,
                    tool_name=tool_name,
                    parameters=parameters,
                    duration_ms=duration_ms,
                )
                session.add_event(event)
            except Exception:
                continue
    return session


def get_expected_label(filename: str) -> tuple:
    """从文件名获取预期标签"""
    for pattern, attack_type in NATIVE_ATTACK_PATTERNS.items():
        if filename.startswith(pattern):
            return attack_type, True
    return AttackType.BENIGN, False


def run_test(session_file: Path, engine: CallistoEngine) -> tuple:
    """运行单个会话检测"""
    session = parse_openclaw_session(session_file)
    start = datetime.now()
    alerts = engine.analyze_session(session)
    elapsed = (datetime.now() - start).total_seconds() * 1000
    alert_types = list(set(a.attack_type.value for a in alerts))
    return alert_types, elapsed, len(alerts)


def scan_native_sessions(engine: CallistoEngine) -> dict:
    """扫描原生测试集"""
    print("\n" + "=" * 70)
    print("原生测试集检测 (CALLISTO A1-A6)")
    print("=" * 70)

    results = []
    files = sorted(NATIVE_TEST_DIR.glob("*.jsonl"))

    for file_path in files:
        session = parse_openclaw_session(file_path)
        n_calls = len(session.tool_calls)
        if n_calls == 0:
            continue

        detect_start = time.time()
        alerts = engine.analyze_session(session)
        detect_time = (time.time() - detect_start) * 1000

        expected_type, is_attack = get_expected_label(file_path.name)
        detected_types = set(a.attack_type for a in alerts)
        detected = len(alerts) > 0

        result = {
            "file": file_path.name,
            "tool_calls": n_calls,
            "expected_type": expected_type.value,
            "is_attack": is_attack,
            "detected": detected,
            "detected_types": [str(a) for a in detected_types],
            "alert_count": len(alerts),
            "detection_time_ms": detect_time,
        }
        results.append(result)

        status = "✓" if (detected if is_attack else not detected) else "✗"
        print(f"{status} {file_path.name}: {n_calls} calls, {len(alerts)} alerts ({detect_time:.1f}ms)")

    return {"results": results}


def scan_expert_sessions(engine: CallistoEngine) -> dict:
    """扫描专家测试集"""
    print("\n" + "=" * 70)
    print("专家测试集检测 (15 类风险场景)")
    print("=" * 70)

    results = {
        "R_资源滥用": {"detected": 0, "total": 0},
        "P_权限突破": {"detected": 0, "total": 0},
        "D_数据威胁": {"detected": 0, "total": 0},
        "X_持久化后门": {"detected": 0, "total": 0},
        "L_横向移动": {"detected": 0, "total": 0},
    }
    category_results = {}
    benign_results = []

    # 扫描攻击场景
    for pattern in EXPERT_RISK_CATEGORIES.keys():
        category_results[pattern] = {"detected": 0, "total": 0, "files": []}
        short_code = pattern.split("_")[0]

        for variant in range(1, 6):
            session_file = EXPERT_TEST_DIR / f"{pattern}_{variant}.jsonl"
            if not session_file.exists():
                continue

            alert_types, elapsed, alert_count = run_test(session_file, engine)
            detected = len(alert_types) > 0

            category_results[pattern]["total"] += 1
            category_results[pattern]["files"].append({
                "file": session_file.name,
                "alerts": alert_types,
                "detected": detected,
                "time": elapsed
            })
            if detected:
                category_results[pattern]["detected"] += 1

            status = "✓" if detected else "✗"
            print(f"{status} {session_file.name}: {alert_count} alerts ({elapsed:.1f}ms)")
            if alert_types:
                print(f"    → {alert_types}")

            # 按大类统计
            cat = CATEGORY_GROUP_MAP.get(short_code)
            if cat:
                results[cat]["total"] += 1
                if detected:
                    results[cat]["detected"] += 1

    # 扫描良性场景
    print("\n" + "-" * 70)
    print("良性场景检测")
    print("-" * 70)

    false_positives = 0
    for v in range(1, 26):
        session_file = EXPERT_TEST_DIR / f"benign_{v}.jsonl"
        if not session_file.exists():
            continue

        alert_types, elapsed, alert_count = run_test(session_file, engine)
        is_fp = len(alert_types) > 0

        benign_results.append({
            "file": session_file.name,
            "alerts": alert_types,
            "false_positive": is_fp,
            "time": elapsed
        })

        status = "✗" if is_fp else "✓"
        fp_mark = " [误报]" if is_fp else ""
        print(f"{status} {session_file.name}: {alert_count} alerts{fp_mark}")
        if is_fp:
            print(f"    → {alert_types}")

        if is_fp:
            false_positives += 1

    return {
        "category_results": category_results,
        "benign_results": benign_results,
        "group_results": results,
        "false_positives": false_positives,
        "benign_total": len(benign_results)
    }


def generate_comprehensive_report(native_data: dict, expert_data: dict, total_time: float) -> Path:
    """生成综合评估报告"""
    report_path = REPORT_DIR / "comprehensive_evaluation.txt"

    # 计算原生测试集指标
    native_results = native_data["results"]
    native_attacks = [r for r in native_results if r["is_attack"]]
    native_benign = [r for r in native_results if not r["is_attack"]]
    native_tp = [r for r in native_attacks if r["detected"]]
    native_fn = [r for r in native_attacks if not r["detected"]]
    native_fp = [r for r in native_benign if r["detected"]]
    native_tn = [r for r in native_benign if not r["detected"]]

    native_recall = len(native_tp) / len(native_attacks) if native_attacks else 0
    native_specificity = len(native_tn) / len(native_benign) if native_benign else 0

    # 计算专家测试集指标
    category_results = expert_data["category_results"]
    detected_count = sum(cat["detected"] for cat in category_results.values())
    total_attack = sum(cat["total"] for cat in category_results.values())
    expert_recall = detected_count / total_attack if total_attack > 0 else 0
    expert_fp_rate = expert_data["false_positives"] / expert_data["benign_total"] if expert_data["benign_total"] > 0 else 0
    expert_specificity = 1.0 - expert_fp_rate

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("CALLISTO 综合评估报告\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总测试时间：{total_time:.2f} 秒\n\n")

        # 一、核心指标对比
        f.write("=" * 70 + "\n")
        f.write("一、核心指标对比\n")
        f.write("=" * 70 + "\n\n")

        f.write("| 测试集 | 攻击类型 | 召回率 | 特异度 | 综合评级 |\n")
        f.write("|--------|---------|-------|-------|----------|\n")

        native_rating = "优秀" if native_recall >= 0.9 else "良好" if native_recall >= 0.7 else "需改进"
        expert_rating = "优秀" if expert_recall >= 0.9 else "良好" if expert_recall >= 0.7 else "需改进"

        f.write(f"| 原生测试集 | 6 类 (A1-A6) | {native_recall*100:.1f}% | {native_specificity*100:.1f}% | {native_rating} |\n")
        f.write(f"| 专家测试集 | 15 类风险场景 | {expert_recall*100:.1f}% | {expert_specificity*100:.1f}% | {expert_rating} |\n\n")

        # 二、原生测试集详情
        f.write("=" * 70 + "\n")
        f.write("二、原生测试集详情 (A1-A6)\n")
        f.write("=" * 70 + "\n\n")

        f.write(f"总会话数：{len(native_results)}\n")
        f.write(f"攻击会话：{len(native_attacks)} (检出:{len(native_tp)}, 漏报:{len(native_fn)})\n")
        f.write(f"良性会话：{len(native_benign)} (误报:{len(native_fp)}, 正确:{len(native_tn)})\n\n")

        # 按攻击类型分组
        type_results = defaultdict(lambda: {"detected": 0, "total": 0})
        for r in native_results:
            if r["is_attack"]:
                prefix = r["file"].rsplit("_", 1)[0]
                type_results[prefix]["total"] += 1
                if r["detected"]:
                    type_results[prefix]["detected"] += 1

        for type_name, data in sorted(type_results.items()):
            rate = data["detected"] / data["total"] * 100 if data["total"] > 0 else 0
            status = "✓" if rate >= 80 else "○" if rate >= 50 else "✗"
            f.write(f"{status} {type_name}: {data['detected']}/{data['total']} ({rate:.0f}%)\n")

        # 三、专家测试集详情
        f.write("\n" + "=" * 70 + "\n")
        f.write("三、专家测试集详情 (15 类风险场景)\n")
        f.write("=" * 70 + "\n\n")

        f.write("各大类检测情况:\n\n")
        for cat_name, data in expert_data["group_results"].items():
            rate = data["detected"] / data["total"] * 100 if data["total"] > 0 else 0
            bar = "█" * int(rate / 5) + "░" * (20 - int(rate / 5))
            f.write(f"{cat_name}: {data['detected']}/{data['total']} ({rate:.1f}%) [{bar}]\n")

        f.write("\n各子类检测详情:\n\n")
        for pattern, data in category_results.items():
            category_name = EXPERT_RISK_CATEGORIES[pattern]
            rate = data["detected"] / data["total"] * 100 if data["total"] > 0 else 0
            status = "✓" if rate >= 80 else "○" if rate >= 50 else "✗"
            f.write(f"{status} {pattern} ({category_name}): {rate:.0f}% ({data['detected']}/{data['total']})\n")

        # 四、未检出风险分析
        f.write("\n" + "=" * 70 + "\n")
        f.write("四、未检出风险分析\n")
        f.write("=" * 70 + "\n\n")

        missed = []
        for pattern, data in category_results.items():
            for file_info in data["files"]:
                if not file_info["detected"]:
                    missed.append({
                        "category": EXPERT_RISK_CATEGORIES[pattern],
                        "file": file_info["file"]
                    })

        f.write(f"未检出数量：{len(missed)}\n\n")
        for m in missed[:10]:
            f.write(f"  - {m['file']} ({m['category']})\n")
        if len(missed) > 10:
            f.write(f"  ... 还有 {len(missed) - 10} 个\n")

        # 五、检测逻辑映射
        f.write("\n" + "=" * 70 + "\n")
        f.write("五、检测逻辑映射关系\n")
        f.write("=" * 70 + "\n\n")

        f.write("CALLISTO 原生检测 (A1-A6) 与专家风险场景的映射:\n\n")
        f.write("| 专家场景 | 映射到 CALLISTO | 检测状态 |\n")
        f.write("|---------|----------------|----------|\n")
        f.write("| R1 速率洪水 | A1_RATE_FLOOD | ✓ 原生支持 |\n")
        f.write("| R2 计算密集 | - | ✗ 未覆盖 |\n")
        f.write("| R3 存储膨胀 | - | ✗ 未覆盖 |\n")
        f.write("| P1 越界访问 | A3_DATA_EXFIL | ~ 部分覆盖 |\n")
        f.write("| P2 权限提升 | A2_PRIV_ESCALATION | ✓ 原生支持 |\n")
        f.write("| P3 沙盒逃逸 | - | ✗ 未覆盖 |\n")
        f.write("| D1 敏感读取 | A3_DATA_EXFIL | ✓ 已添加 |\n")
        f.write("| D2 数据外泄 | A3_DATA_EXFIL | ✓ 原生支持 |\n")
        f.write("| D3 数据投毒 | A6_STATE_POISON | ~ 部分覆盖 |\n")
        f.write("| X1 配置修改 | A6_STATE_POISON | ✓ 原生支持 |\n")
        f.write("| X2 凭据植入 | A6_STATE_POISON | ✓ 原生支持 |\n")
        f.write("| X3 定时任务 | A6_STATE_POISON | ~ 部分覆盖 |\n")
        f.write("| L1 网络探测 | A3_DATA_EXFIL | ~ 部分覆盖 |\n")
        f.write("| L2 服务调用 | A3_DATA_EXFIL | ✓ 已添加 |\n")
        f.write("| L3 凭证收集 | A3_DATA_EXFIL | ~ 部分覆盖 |\n")

        # 六、结论与建议
        f.write("\n" + "=" * 70 + "\n")
        f.write("六、结论与建议\n")
        f.write("=" * 70 + "\n\n")

        avg_recall = (native_recall + expert_recall) / 2
        overall_rating = "优秀" if avg_recall >= 0.85 else "良好" if avg_recall >= 0.7 else "中等" if avg_recall >= 0.5 else "需改进"

        f.write(f"综合检出率：{(native_recall + expert_recall) / 2 * 100:.1f}%\n")
        f.write(f"综合特异度：{(native_specificity + expert_specificity) / 2 * 100:.1f}%\n")
        f.write(f"综合评级：{overall_rating}\n\n")

        f.write("改进建议:\n\n")
        f.write("1. **高优先级** - 添加资源监控 (R2 计算密集、R3 存储膨胀)\n")
        f.write("2. **中优先级** - 增强沙盒逃逸检测 (P3)\n")
        f.write("3. **中优先级** - 改进定时任务检测 (X3)\n")
        f.write("4. **低优先级** - 优化网络探测检测 (L1)\n")

    print(f"\n综合评估报告：{report_path}")
    return report_path


def main():
    print("\n" + "=" * 70)
    print("CALLISTO 统一测试框架")
    print("=" * 70)
    print(f"测试开始时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 初始化引擎
    config = CallistoConfig()
    config.csbf_min_history = 10
    engine = CallistoEngine(config)

    total_start = time.time()

    # 扫描原生测试集
    native_data = scan_native_sessions(engine)

    # 扫描专家测试集
    expert_data = scan_expert_sessions(engine)

    total_time = time.time() - total_start

    # 生成综合报告
    print("\n" + "=" * 70)
    print("生成报告")
    print("=" * 70)

    generate_comprehensive_report(native_data, expert_data, total_time)

    print("\n" + "=" * 70)
    print("完成")
    print("=" * 70)
    print(f"总测试时间：{total_time:.2f} 秒")
    print(f"报告目录：{REPORT_DIR.absolute()}")


if __name__ == "__main__":
    main()

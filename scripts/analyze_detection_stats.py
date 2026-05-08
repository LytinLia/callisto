#!/usr/bin/env python3
"""
CALLISTO 检测结果统计分析

分析检测结果的分布、平均值、标准差等统计指标
"""

import json
import os
import sys
import time
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from dataclasses import dataclass
from typing import List, Dict, Tuple
import math

sys.path.insert(0, '.')

from callisto.collector.models import Session
from callisto.engine import CallistoEngine
from callisto.config import CallistoConfig

# 测试目录
NATIVE_TEST_DIR = Path("./test_sessions")
EXPERT_TEST_DIR = Path("./expert_test_sessions")


@dataclass
class TestResult:
    """测试结果"""
    category: str
    subcategory: str
    file: str
    num_calls: int
    num_alerts: int
    detection_time_ms: float
    detected: bool
    alert_types: List[str]


def parse_openclaw_session(path: Path) -> Session:
    """解析会话文件"""
    session = Session(session_id=path.stem)
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)

                if raw.get("type") in ("toolResult", "toolCall"):
                    tool_name = raw.get("toolName") or raw.get("tool", "")
                    parameters = raw.get("parameters", {})
                    event_id = raw.get("id", "")
                    timestamp = raw.get("timestamp", time.time())
                    duration_ms = raw.get("durationMs", 0)
                elif raw.get("type") == "message":
                    msg = raw.get("message", {})
                    if msg.get("role") == "user":
                        continue
                    tool_name = raw.get("toolName") or msg.get("toolName") or raw.get("tool", "")
                    if not tool_name:
                        continue
                    parameters = raw.get("parameters", {})
                    event_id = raw.get("id", "")
                    ts_raw = raw.get("timestamp", "")
                    if isinstance(ts_raw, str):
                        timestamp = time.time()
                    else:
                        timestamp = ts_raw if ts_raw else time.time()
                    duration_ms = raw.get("details", {}).get("durationMs", 0)
                else:
                    continue

                if not tool_name:
                    continue

                from callisto.collector.models import CallEvent, EventType
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


def run_test(session_file: Path, engine: CallistoEngine) -> Tuple[List[str], float, int]:
    """运行单个测试"""
    session = parse_openclaw_session(session_file)
    start = time.time()
    alerts = engine.analyze_session(session)
    elapsed = (time.time() - start) * 1000
    alert_types = list(set(a.attack_type.value for a in alerts))
    return alert_types, elapsed, len(alerts)


def get_category_info(filename: str) -> Tuple[str, str, bool]:
    """获取文件所属类别和是否为攻击"""
    name = filename.replace('.jsonl', '')

    # 原生攻击类型
    native_prefixes = {
        'attack_rate_flood': ('A1_RateFlood', '速率洪水', True),
        'attack_priv_escalation': ('A2_PrivEsc', '权限升级', True),
        'attack_data_exfil': ('A3_DataExfil', '数据外泄', True),
        'attack_behavior_drift': ('A4_BehaviorDrift', '行为漂移', True),
        'attack_temporal_violation': ('A5_TemporalViol', '时序违例', True),
        'attack_state_poison': ('A6_StatePoison', '状态投毒', True),
        'benign': ('Benign', '良性', False),
    }

    # 专家类型
    expert_prefixes = {
        'r1_rate_flood': ('R1', '速率洪水', True),
        'r2_compute_intensive': ('R2', '计算密集', True),
        'r3_storage_bloat': ('R3', '存储膨胀', True),
        'p1_boundary_violation': ('P1', '越界访问', True),
        'p2_privilege_escalation': ('P2', '权限提升', True),
        'p3_sandbox_escape': ('P3', '沙盒逃逸', True),
        'd1_sensitive_read': ('D1', '敏感读取', True),
        'd2_data_exfil': ('D2', '数据外泄', True),
        'd3_data_poisoning': ('D3', '数据投毒', True),
        'x1_config_modification': ('X1', '配置修改', True),
        'x2_credential_injection': ('X2', '凭据植入', True),
        'x3_scheduled_task': ('X3', '定时任务', True),
        'l1_network_recon': ('L1', '网络探测', True),
        'l2_service_call': ('L2', '服务调用', True),
        'l3_credential_harvest': ('L3', '凭证收集', True),
        'benign': ('Benign', '良性', False),
    }

    for prefix, (code, desc, is_attack) in native_prefixes.items():
        if name.startswith(prefix):
            return ('Native', code, is_attack)

    for prefix, (code, desc, is_attack) in expert_prefixes.items():
        if name.startswith(prefix):
            return (f'Expert_{prefix.split("_")[0].upper()}', code, is_attack)

    return ('Unknown', 'Unknown', False)


def calculate_stats(values: List[float]) -> Dict[str, float]:
    """计算统计指标"""
    if not values:
        return {'mean': 0, 'std': 0, 'min': 0, 'max': 0, 'median': 0}

    n = len(values)
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n if n > 1 else 0
    std = math.sqrt(variance)
    sorted_vals = sorted(values)
    median = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2

    return {
        'mean': mean,
        'std': std,
        'min': min(values),
        'max': max(values),
        'median': median,
        'count': n
    }


def main():
    print("=" * 80)
    print("CALLISTO 检测结果统计分析")
    print("=" * 80)
    print(f"分析时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # 初始化引擎
    config = CallistoConfig()
    engine = CallistoEngine(config)

    results: List[TestResult] = []

    # ========== 扫描原生测试集 ==========
    print("扫描原生测试集...")
    native_files = sorted(NATIVE_TEST_DIR.glob("*.jsonl"))

    for file_path in native_files:
        # 跳过 realtime_test.jsonl
        if file_path.name == "realtime_test.jsonl":
            continue

        session = parse_openclaw_session(file_path)
        if len(session.tool_calls) == 0:
            continue

        detect_start = time.time()
        alerts = engine.analyze_session(session)
        detect_time = (time.time() - detect_start) * 1000

        alert_types = [a.attack_type.value for a in alerts]
        category, subcategory, is_attack = get_category_info(file_path.name)

        results.append(TestResult(
            category=category,
            subcategory=subcategory,
            file=file_path.name,
            num_calls=len(session.tool_calls),
            num_alerts=len(alerts),
            detection_time_ms=detect_time,
            detected=len(alerts) > 0,
            alert_types=alert_types
        ))

    # ========== 扫描专家测试集 ==========
    print("扫描专家测试集...")
    expert_files = sorted(EXPERT_TEST_DIR.glob("*.jsonl"))

    for file_path in expert_files:
        session = parse_openclaw_session(file_path)
        if len(session.tool_calls) == 0:
            continue

        detect_start = time.time()
        alerts = engine.analyze_session(session)
        detect_time = (time.time() - detect_start) * 1000

        alert_types = [a.attack_type.value for a in alerts]
        category, subcategory, is_attack = get_category_info(file_path.name)

        results.append(TestResult(
            category=category,
            subcategory=subcategory,
            file=file_path.name,
            num_calls=len(session.tool_calls),
            num_alerts=len(alerts),
            detection_time_ms=detect_time,
            detected=len(alerts) > 0,
            alert_types=alert_types
        ))

    # ========== 统计分析 ==========
    print("\n" + "=" * 80)
    print("一、总体统计")
    print("=" * 80)

    total = len(results)
    attacks = [r for r in results if r.subcategory != 'Benign']
    benign = [r for r in results if r.subcategory == 'Benign']

    # 召回率相关
    tp = sum(1 for r in attacks if r.detected)
    fn = sum(1 for r in attacks if not r.detected)
    recall = tp / len(attacks) * 100 if attacks else 0

    # 特异度相关
    tn = sum(1 for r in benign if not r.detected)
    fp = sum(1 for r in benign if r.detected)
    specificity = tn / len(benign) * 100 if benign else 0
    fpr = fp / len(benign) * 100 if benign else 0

    print(f"总会话数：{total}")
    print(f"攻击会话：{len(attacks)} (检出:{tp}, 漏报:{fn})")
    print(f"良性会话：{len(benign)} (正确:{tn}, 误报:{fp})")
    print()
    print(f"召回率 (Recall): {recall:.1f}%")
    print(f"特异度 (Specificity): {specificity:.1f}%")
    print(f"误报率 (FPR): {fpr:.1f}%")

    # ========== 检测时间分析 ==========
    print("\n" + "=" * 80)
    print("二、检测时间分析 (毫秒)")
    print("=" * 80)

    all_times = [r.detection_time_ms for r in results]
    attack_times = [r.detection_time_ms for r in attacks]
    benign_times = [r.detection_time_ms for r in benign]

    time_stats = calculate_stats(all_times)
    print(f"\n总体检测时间:")
    print(f"  平均值：{time_stats['mean']:.2f} ms")
    print(f"  中位数：{time_stats['median']:.2f} ms")
    print(f"  标准差：{time_stats['std']:.2f} ms")
    print(f"  最小值：{time_stats['min']:.2f} ms")
    print(f"  最大值：{time_stats['max']:.2f} ms")

    # ========== 各类别检测效果 ==========
    print("\n" + "=" * 80)
    print("三、各类别检测效果")
    print("=" * 80)

    category_stats = defaultdict(lambda: {'tp': 0, 'fn': 0, 'fp': 0, 'tn': 0, 'total': 0})

    for r in results:
        key = r.subcategory
        category_stats[key]['total'] += 1

        if r.subcategory == 'Benign':
            if r.detected:
                category_stats[key]['fp'] += 1
            else:
                category_stats[key]['tn'] += 1
        else:
            if r.detected:
                category_stats[key]['tp'] += 1
            else:
                category_stats[key]['fn'] += 1

    print(f"\n{'类别':<20} {'检测':>8} {'漏报':>8} {'召回率':>10} {'平均时间 (ms)':>15}")
    print("-" * 65)

    for cat, stats in sorted(category_stats.items(), key=lambda x: -x[1]['tp']/max(x[1]['tp']+x[1]['fn'], 1)):
        total_cat = stats['tp'] + stats['fn'] if stats['tp'] + stats['fn'] > 0 else stats['tn'] + stats['fp']
        if cat == 'Benign':
            rate = stats['tn'] / total_cat * 100 if total_cat > 0 else 0
        else:
            rate = stats['tp'] / total_cat * 100 if total_cat > 0 else 0

        cat_results = [r for r in results if r.subcategory == cat]
        avg_time = sum(r.detection_time_ms for r in cat_results) / len(cat_results) if cat_results else 0

        if cat == 'Benign':
            print(f"{cat:<20} {stats['tn']:>8} {stats['fp']:>8} {rate:>9.1f}% {avg_time:>15.2f}")
        else:
            print(f"{cat:<20} {stats['tp']:>8} {stats['fn']:>8} {rate:>9.1f}% {avg_time:>15.2f}")

    # ========== 告警数量分布 ==========
    print("\n" + "=" * 80)
    print("四、告警数量分布")
    print("=" * 80)

    alert_counts = defaultdict(int)
    for r in results:
        alert_counts[r.num_alerts] += 1

    print(f"\n{'告警数':>10} {'会话数':>10} {'占比':>10}")
    print("-" * 35)
    for count in sorted(alert_counts.keys()):
        pct = alert_counts[count] / total * 100
        print(f"{count:>10} {alert_counts[count]:>10} {pct:>9.1f}%")

    # ========== 告警类型分布 ==========
    print("\n" + "=" * 80)
    print("五、告警类型分布")
    print("=" * 80)

    alert_type_counts = defaultdict(int)
    for r in results:
        for at in r.alert_types:
            alert_type_counts[at] += 1

    print(f"\n{'告警类型':<30} {'出现次数':>10} {'占比':>10}")
    print("-" * 55)
    for atype, count in sorted(alert_type_counts.items(), key=lambda x: -x[1]):
        total_alerts = sum(alert_type_counts.values())
        pct = count / total_alerts * 100 if total_alerts > 0 else 0
        print(f"{atype:<30} {count:>10} {pct:>9.1f}%")

    # ========== 按调用次数分组分析 ==========
    print("\n" + "=" * 80)
    print("六、按调用次数分组分析")
    print("=" * 80)

    call_bins = [(0, 5), (5, 10), (10, 20), (20, 50), (50, 100), (100, float('inf'))]
    bin_names = ["1-5", "6-10", "11-20", "21-50", "51-100", "100+"]

    print(f"\n{'调用次数':>12} {'总会话':>10} {'检出':>8} {'漏报':>8} {'召回率':>10}")
    print("-" * 50)

    for (low, high), bin_name in zip(call_bins, bin_names):
        bin_results = [r for r in attacks if low < r.num_calls <= high]
        if not bin_results:
            continue

        detected = sum(1 for r in bin_results if r.detected)
        missed = len(bin_results) - detected
        rate = detected / len(bin_results) * 100

        avg_time = sum(r.detection_time_ms for r in bin_results) / len(bin_results)

        print(f"{bin_name:>12} {len(bin_results):>10} {detected:>8} {missed:>8} {rate:>9.1f}%")

    # ========== 输出总结 ==========
    print("\n" + "=" * 80)
    print("总结")
    print("=" * 80)

    print(f"""
测试覆盖:
  - 总会话数：{total}
  - 攻击会话：{len(attacks)}
  - 良性会话：{len(benign)}

检测性能:
  - 召回率：{recall:.1f}% ({tp}/{len(attacks)})
  - 特异度：{specificity:.1f}% ({tn}/{len(benign)})
  - 误报率：{fpr:.1f}%

检测效率:
  - 平均检测时间：{time_stats['mean']:.2f} ms
  - 中位检测时间：{time_stats['median']:.2f} ms

最强检测类别 (召回率 100%):
""")

    for cat, stats in category_stats.items():
        if cat == 'Benign':
            continue
        total_cat = stats['tp'] + stats['fn']
        if total_cat > 0 and stats['tp'] / total_cat == 1.0:
            print(f"  ✓ {cat}")

    print(f"\n需改进类别 (召回率 < 50%):")
    for cat, stats in category_stats.items():
        if cat == 'Benign':
            continue
        total_cat = stats['tp'] + stats['fn']
        if total_cat > 0 and stats['tp'] / total_cat < 0.5:
            rate = stats['tp'] / total_cat * 100
            print(f"  ✗ {cat}: {rate:.1f}%")

    print()


if __name__ == "__main__":
    main()

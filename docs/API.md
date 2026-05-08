# CALLISTO API 参考文档

## 核心模块

### `callisto.engine`

主检测引擎模块。

#### `CallistoEngine`

```python
from callisto.engine import CallistoEngine
from callisto.config import CallistoConfig

engine = CallistoEngine(config: CallistoConfig | None = None)
```

**主要方法：**

| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| `analyze_session` | `session: Session` | `list[Alert]` | 分析会话，返回告警列表 |
| `is_blocked` | - | `bool` | 检查是否触发熔断 |
| `train_fingerprints` | `sessions: list[Session]` | `None` | 从历史会话训练指纹 |

**示例：**
```python
engine = CallistoEngine()
alerts = engine.analyze_session(session)
if engine.is_blocked():
    print("Agent blocked")
```

---

### `callisto.config`

配置模块。

#### `CallistoConfig`

```python
from callisto.config import CallistoConfig

config = CallistoConfig(
    # 特征提取
    context_window: int = 10,
    embedding_dim: int = 64,
    
    # CRS 配置
    crs_samples: int = 30,
    crs_threshold: float = 0.7,
    
    # MA-BOCPD 配置
    bocpd_hazard_base: float = 1/25,
    bocpd_threshold: float = 0.5,
    bocpd_run_length_cap: int = 50,
    
    # CSBF 配置
    csbf_distance_threshold: float = 3.0,
    csbf_min_history: int = 5,
    
    # 响应配置
    alert_cooldown: float = 5.0,
    circuit_breaker_threshold: int = 3,
    
    # 时序检测
    burst_window: float = 5.0,
    burst_count_threshold: int = 8,
    sensitive_chain_min: int = 3,
    
    # 持久化
    fingerprint_path: Path | None = None,
)
```

---

### `callisto.collector.models`

数据模型定义。

#### `Session`

```python
@dataclass
class Session:
    session_id: str
    agent_id: str
    events: list[CallEvent]
    start_time: float
    end_time: float
    metadata: dict
    
    @property
    def duration(self) -> float
    @property
    def tool_calls(self) -> list[CallEvent]
    
    def add_event(self, event: CallEvent) -> None
```

#### `CallEvent`

```python
@dataclass
class CallEvent:
    event_id: str
    session_id: str
    agent_id: str
    timestamp: float
    event_type: EventType
    tool_name: str
    parameters: dict
    result: Any
    duration_ms: float
    label: AttackType  # 仅用于评估
```

#### `Alert`

```python
@dataclass
class Alert:
    alert_id: str
    timestamp: float
    session_id: str
    risk_level: RiskLevel
    attack_type: AttackType
    source_module: str
    trigger_events: list[str]
    score: float
    explanation: str
```

#### 枚举类型

```python
class RiskLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AttackType(Enum):
    A1_RATE_FLOOD = "rate_flood"
    A2_PRIV_ESCALATION = "priv_escalation"
    A3_DATA_EXFIL = "data_exfil"
    A4_BEHAVIOR_DRIFT = "behavior_drift"
    A5_TEMPORAL_VIOLATION = "temporal_violation"
    A6_STATE_POISON = "state_poison"
    BENIGN = "benign"

class EventType(Enum):
    TOOL_CALL = "toolCall"
    TOOL_RESULT = "toolResult"
    MESSAGE = "message"
    MODEL_CHANGE = "model_change"
    CUSTOM = "custom"
```

---

### `callisto.features`

特征提取模块。

#### `TemporalExtractor`

```python
from callisto.features.temporal import TemporalExtractor

extractor = TemporalExtractor(window_size: int = 10)
features = extractor.extract(calls: list[CallEvent])
```

#### `StructuralExtractor`

```python
from callisto.features.structural import StructuralExtractor

extractor = StructuralExtractor(
    min_snippet_len: int = 16,
    trivial_values: set[str] = {"true", "false", "null", ...}
)
graph, features = extractor.extract(calls: list[CallEvent])
```

返回的 `graph` 是 `networkx.DiGraph`，节点表示工具调用，边表示数据依赖。

#### `SemanticExtractor`

```python
from callisto.features.semantic import SemanticExtractor

extractor = SemanticExtractor(embedding_dim: int = 64)
features = extractor.extract_event(event: CallEvent)
vector = features.to_vector()  # numpy.ndarray

# 批量提取
sequence = extractor.extract_sequence(events: list[CallEvent])
summary = extractor.extract_session_summary(events: list[CallEvent])
```

---

### `callisto.detection`

检测算法模块。

#### `CausalResponsibilityScorer` (CRS)

```python
from callisto.detection.causal import CausalResponsibilityScorer

crs = CausalResponsibilityScorer(
    num_samples: int = 30,
    threshold: float = 0.7,
    safety_fn: Callable | None = None,
)

# 评分
result = crs.score(graph: nx.DiGraph)
print(result.scores)       # event_id -> score
print(result.critical_path)  # 关键路径

# 直接检测
alert = crs.detect(graph: nx.DiGraph)
```

#### `MABOCPD` (MA-BOCPD)

```python
from callisto.detection.changepoint import MABOCPD, MetaAdaptiveHazard

hazard = MetaAdaptiveHazard(
    base_lam: float = 1.0,
    dim: int = 64,
)

bocpd = MABOCPD(
    dim: int = 64,
    hazard: MetaAdaptiveHazard,
    threshold: float = 0.5,
    run_length_cap: int = 50,
)

# 在线检测
for event in events:
    embedding = semantic.extract_event(event).to_vector()
    alert = bocpd.detect(embedding, session_id="...")
```

#### `CrossSessionFingerprinter` (CSBF)

```python
from callisto.detection.fingerprint import CrossSessionFingerprinter

csbf = CrossSessionFingerprinter(
    distance_threshold: float = 3.0,
    min_history: int = 5,
    adaptive_threshold: bool = True,
)

# 训练
for session in benign_sessions:
    csbf.fit_session(session)

# 检测
alert = csbf.detect(new_session)

# 持久化
csbf.save(Path("./fingerprints.json"))
csbf = CrossSessionFingerprinter.load(Path("./fingerprints.json"))
```

---

### `callisto.response`

响应处理模块。

#### `AlertRanker`

```python
from callisto.response.alert_ranker import AlertRanker

ranker = AlertRanker(cooldown: float = 5.0)
ranked_alerts = ranker.process(alerts: list[Alert])
```

功能：去重、排序、冷却处理。

#### `CircuitBreaker`

```python
from callisto.response.circuit_breaker import CircuitBreaker

breaker = CircuitBreaker(threshold: int = 3)

for alert in alerts:
    breaker.record_alert(alert)

if breaker.should_block():
    print("触发熔断")
```

#### `AlertExplainer`

```python
from callisto.response.explainer import AlertExplainer

explainer = AlertExplainer()

# 单个告警解释
explanation = explainer.explain(alert)

# 批量解释
report = explainer.explain_batch(alerts)
```

---

## 攻击模拟器

### `callisto.attacks.simulator`

```python
from callisto.attacks.simulator import (
    generate_benign_session,
    generate_rate_flood,
    generate_priv_escalation,
    generate_data_exfil,
    generate_behavior_drift,
    generate_temporal_violation,
    generate_state_poison,
    generate_dataset,
)

# 生成单个会话
session = generate_benign_session(n_calls=30, agent_id="agent_0", seed=42)
session = generate_rate_flood(n_calls=50, burst_size=20)
session = generate_priv_escalation()
session = generate_data_exfil()
session = generate_behavior_drift(n_normal=20, n_drifted=15)
session = generate_temporal_violation()
session = generate_state_poison()

# 生成完整数据集
sessions = generate_dataset(
    n_benign: int = 100,
    n_per_attack: int = 30,
    seed: int = 42,
)
```

---

## 评估工具

### `callisto.evaluation.metrics`

```python
from callisto.evaluation.metrics import (
    evaluate_detector,
    per_attack_metrics,
    detection_latency,
    EvalMetrics,
)

# 评估检测器
metrics = evaluate_detector(sessions, predicted_alerts)
print(f"F1: {metrics.f1:.4f}")

# 每类攻击的指标
per_attack = per_attack_metrics(sessions, predicted_alerts)

# 检测延迟
latencies = detection_latency(sessions, predicted_alerts)
```

#### `EvalMetrics`

```python
@dataclass
class EvalMetrics:
    tp: int  # 真阳性
    fp: int  # 假阳性
    tn: int  # 真阴性
    fn: int  # 假阴性
    
    @property
    def precision(self) -> float
    @property
    def recall(self) -> float
    @property
    def f1(self) -> float
    @property
    def fpr(self) -> float
    @property
    def accuracy(self) -> float
```

---

## 完整示例

### 示例 1: 实时检测

```python
import time
from callisto.engine import CallistoEngine
from callisto.collector.models import Session, CallEvent

engine = CallistoEngine()
session = Session(session_id="live_001", agent_id="assistant")

# 模拟实时事件流
for i in range(20):
    event = CallEvent(
        tool_name="read_file" if i % 3 == 0 else "search",
        parameters={"query": f"task_{i}"},
        timestamp=time.time(),
    )
    session.add_event(event)
    time.sleep(0.1)
    
    # 每 5 个事件检测一次
    if (i + 1) % 5 == 0:
        alerts = engine.analyze_session(session)
        for alert in alerts:
            print(f"[{alert.risk_level.name}] {alert.explanation}")
```

### 示例 2: 批量评估

```python
from callisto.engine import CallistoEngine
from callisto.attacks.simulator import generate_dataset
from callisto.evaluation.metrics import evaluate_detector

# 生成数据
sessions = generate_dataset(n_benign=50, n_per_attack=15)

# 创建引擎并训练
engine = CallistoEngine()
benign = [s for s in sessions if s.events[0].label.value == "benign"][:20]
engine.train_fingerprints(benign)

# 批量检测
all_alerts = []
for session in sessions:
    alerts = engine.analyze_session(session)
    all_alerts.append(alerts)

# 评估
metrics = evaluate_detector(sessions, all_alerts)
print(f"Precision: {metrics.precision:.4f}")
print(f"Recall: {metrics.recall:.4f}")
print(f"F1: {metrics.f1:.4f}")
```

### 示例 3: 自定义检测器

```python
import networkx as nx
from callisto.collector.models import Alert, RiskLevel, AttackType

class CustomDetector:
    """自定义检测器示例：检测特定工具模式。"""
    
    def __init__(self, target_tools: list[str], threshold: int = 3):
        self.target_tools = set(target_tools)
        self.threshold = threshold
    
    def detect(self, session: Session) -> Alert | None:
        count = sum(1 for e in session.tool_calls 
                    if e.tool_name in self.target_tools)
        
        if count >= self.threshold:
            return Alert(
                timestamp=time.time(),
                session_id=session.session_id,
                risk_level=RiskLevel.MEDIUM,
                attack_type=AttackType.A1_RATE_FLOOD,
                source_module="CustomDetector",
                score=count / self.threshold,
                explanation=f"Detected {count} invocations of sensitive tools",
            )
        return None

# 使用
detector = CustomDetector(["exec", "shell"], threshold=2)
alert = detector.detect(session)
```

---

## 故障排除

### 常见问题

**导入错误**
```python
# 确保使用正确的包路径
from callisto.engine import CallistoEngine  # 正确
from engine import CallistoEngine           # 错误
```

**指纹版本不兼容**
```python
# 重新训练指纹
engine = CallistoEngine(config)
engine.train_fingerprints(sessions)
```

**维度不匹配**
```python
# 确保 embedding_dim 一致
config = CallistoConfig(embedding_dim=64)
extractor = SemanticExtractor(embedding_dim=64)
```

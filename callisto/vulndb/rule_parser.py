"""
漏洞版本规则解析器。

将 AI-Infra-Guard 的版本约束 DSL 移植为 Python。
支持的语法：
  version < "X.Y.Z"
  version <= "X.Y.Z"
  version > "X.Y.Z"
  version >= "X.Y.Z"
  version == "X.Y.Z"
  version = "X.Y.Z"
  version != "X.Y.Z"
  is_internal == "true"
  逻辑组合：&&  ||  ()

示例：
  version < "2026.2.23"
  version >= "2026.2.13" && version < "2026.3.25"
  version <= "2026.2.21" || version = "2026.2.21-1"
"""

import re
from dataclasses import dataclass
from packaging.version import Version, InvalidVersion


# ================================
# 版本归一化
# ================================

def normalize_version(v: str) -> str:
    """将版本号字符串归一化为 packaging.version 可解析的格式。

    处理：
    - 去除 'v' 前缀
    - 将字母后缀映射为 .0 格式（如 2026.2a -> 2026.2.0a0）
    - latest -> 999999.0.0
    """
    v = v.strip()
    if v.lower() == "latest":
        return "999999.0.0"
    if v.startswith("v"):
        v = v[1:]
    return v


def parse_version(v: str) -> Version | None:
    """安全地解析版本号。"""
    try:
        return Version(normalize_version(v))
    except (InvalidVersion, ValueError):
        return None


# ================================
# 词法分析
# ================================

@dataclass
class Token:
    type: str
    value: str

    def __repr__(self):
        return f"Token({self.type}, {self.value!r})"


_KEYWORDS = {"version", "is_internal"}
_OPERATORS = {"<=", ">=", "!=", "==", "=", "<", ">", "&&", "||", "(", ")"}


def tokenize(rule: str) -> list[Token]:
    """将规则字符串词法分析为 Token 列表。"""
    tokens = []
    i = 0
    s = rule.strip()

    while i < len(s):
        # 跳过空白
        if s[i].isspace():
            i += 1
            continue

        # 字符串字面量
        if s[i] in ('"', "'"):
            quote = s[i]
            j = i + 1
            while j < len(s) and s[j] != quote:
                if s[j] == '\\':
                    j += 1
                j += 1
            if j >= len(s):
                raise ValueError(f"未闭合的字符串: {s[i:]}")
            tokens.append(Token("STRING", s[i + 1: j]))
            i = j + 1
            continue

        # 双字符运算符
        if i + 1 < len(s) and s[i: i + 2] in ("&&", "||", "<=", ">=", "!=" , "=="):
            op = s[i: i + 2]
            if op == "==":
                op = "="
            tokens.append(Token("OP", op))
            i += 2
            continue

        # 单字符运算符
        if s[i] in "<>=!()":
            tokens.append(Token("OP", s[i]))
            i += 1
            continue

        # 关键字/标识符
        if s[i].isalpha() or s[i] == '_':
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] in "_."):
                j += 1
            word = s[i: j]
            if word in _KEYWORDS:
                tokens.append(Token("KEYWORD", word))
            else:
                tokens.append(Token("IDENT", word))
            i = j
            continue

        raise ValueError(f"未知字符 '{s[i]}' 在位置 {i}")

    return tokens


# ================================
# 语法分析 + 求值
# ================================

class Parser:
    """递归下降解析器，直接求值版本规则。"""

    def __init__(self, tokens: list[Token], detected_version: str, is_internal: bool = False):
        self.tokens = tokens
        self.pos = 0
        self.detected = detected_version
        self.detected_version = parse_version(detected_version)
        self.is_internal = is_internal

    def peek(self) -> Token | None:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def consume(self) -> Token | None:
        tok = self.peek()
        self.pos += 1
        return tok

    def expect(self, tok_type: str, value: str | None = None) -> Token:
        tok = self.consume()
        if tok is None:
            raise ValueError(f"期望 {tok_type}({value})，但到达末尾")
        if tok.type != tok_type:
            raise ValueError(f"期望 {tok_type}，得到 {tok.type} ({tok.value!r})")
        if value is not None and tok.value != value:
            raise ValueError(f"期望 {value}，得到 {tok.value!r}")
        return tok

    def parse(self) -> bool:
        """解析并返回规则是否匹配。"""
        if not self.tokens:
            # 空规则 = 匹配所有
            return True
        result = self.parse_or()
        return result

    # or_expr  = and_expr ("||" and_expr)*
    def parse_or(self) -> bool:
        left = self.parse_and()
        while self.peek() and self.peek().type == "OP" and self.peek().value == "||":
            self.consume()
            right = self.parse_and()
            left = left or right
        return left

    # and_expr = primary ("&&" primary)*
    def parse_and(self) -> bool:
        left = self.parse_primary()
        while self.peek() and self.peek().type == "OP" and self.peek().value == "&&":
            self.consume()
            right = self.parse_primary()
            left = left and right
        return left

    # primary = "(" or_expr ")" | comparison
    def parse_primary(self) -> bool:
        tok = self.peek()
        if tok is None:
            return True
        if tok.type == "OP" and tok.value == "(":
            self.consume()
            result = self.parse_or()
            self.expect("OP", ")")
            return result
        return self.parse_comparison()

    # comparison = (version | is_internal) OP value
    def parse_comparison(self) -> bool:
        tok = self.consume()
        if tok is None:
            raise ValueError("意外的规则结束")

        if tok.type == "KEYWORD" and tok.value == "version":
            op_tok = self.expect("OP")
            val_tok = self.expect("STRING")
            return self.compare_version(op_tok.value, val_tok.value)

        if tok.type == "KEYWORD" and tok.value == "is_internal":
            self.expect("OP", "=")
            val_tok = self.expect("STRING")
            return self.is_internal == (val_tok.value.lower() == "true")

        raise ValueError(f"意外的 token: {tok}")

    def compare_version(self, op: str, threshold_str: str) -> bool:
        """比较检测版本与阈值版本。"""
        if self.detected_version is None:
            # 无法解析版本时，保守匹配（视为有漏洞）
            return True

        threshold = parse_version(threshold_str)
        if threshold is None:
            return True

        try:
            dv = self.detected_version
            tv = threshold
            if op == "<":
                return dv < tv
            elif op == "<=":
                return dv <= tv
            elif op == ">":
                return dv > tv
            elif op == ">=":
                return dv >= tv
            elif op == "=":
                return dv == tv
            elif op == "!=":
                return dv != tv
            else:
                raise ValueError(f"未知运算符: {op}")
        except TypeError:
            return True


def eval_rule(rule: str, detected_version: str, is_internal: bool = False) -> bool:
    """求值单条规则，返回是否匹配（即是否存在漏洞）。"""
    tokens = tokenize(rule)
    parser = Parser(tokens, detected_version, is_internal)
    return parser.parse()

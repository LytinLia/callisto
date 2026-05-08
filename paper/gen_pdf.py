#!/usr/bin/env python3
"""Generate CALLISTO paper as PDF using raw PDF 1.4 syntax."""

import struct
import time

def make_pdf():
    objects = []  # list of (obj_num, content_bytes)

    def add_obj(content: str) -> int:
        obj_num = len(objects) + 1
        objects.append((obj_num, content if isinstance(content, bytes) else content.encode('latin-1')))
        return obj_num

    # ---- Catalog (obj 1)
    add_obj(f"""1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj""")

    # ---- Pages (obj 2) - will update Kids later
    add_obj(f"""2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj""")

    # ---- Font: Times-Roman (obj 3)
    add_obj("""3 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman /Encoding /WinAnsiEncoding >>
endobj""")

    # ---- Font: Times-Bold (obj 4)
    add_obj("""4 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Times-Bold /Encoding /WinAnsiEncoding >>
endobj""")

    # ---- Font: Times-Italic (obj 5)
    add_obj("""5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Times-Italic /Encoding /WinAnsiEncoding >>
endobj""")

    # ---- Font: Helvetica (obj 6)
    add_obj("""6 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>
endobj""")

    # ---- Font: Helvetica-Bold (obj 7)
    add_obj("""7 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>
endobj""")

    # ---- Font: Courier (obj 8) - for code/monospace
    add_obj("""8 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>
endobj""")

    # ---- Font: Courier-Bold (obj 9)
    add_obj("""9 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>
endobj""")

    # ============================================================
    # PAGE CONTENT GENERATION
    # ============================================================

    # Page dimensions: A4 (595.28 x 841.89 points)
    # Single column, 72pt margins
    page_w = 595.28
    page_h = 841.89
    margin = 50
    text_w = page_w - 2 * margin
    text_h = page_h - 2 * margin - 40  # extra for header/footer

    # Current position tracking
    y = page_h - margin  # top of text area
    page_contents = []  # list of stream content strings per page
    current_stream = []

    def flush_page():
        nonlocal y, current_stream
        if current_stream:
            page_contents.append('\n'.join(current_stream))
        current_stream = []
        y = page_h - margin

    def sanitize_pdf_text(s):
        """Replace non-latin-1 characters with ASCII equivalents."""
        replacements = {
            '—': '--',   # em dash
            '–': '-',    # en dash
            '‘': "'",    # left single quote
            '’': "'",    # right single quote
            '“': '"',    # left double quote
            '”': '"',    # right double quote
            '…': '...',  # ellipsis
            '•': '-',    # bullet
            '≥': '>=',   # greater than or equal
            '≤': '<=',   # less than or equal
            '→': '->',   # right arrow
            '×': 'x',    # multiplication sign
            '·': '*',    # middle dot
            '∈': 'in',   # element of
            '∉': 'not in', # not element of
            '≠': '!=',   # not equal
            '≈': '~=',   # approximately equal
            'α': 'alpha', # Greek alpha
            'β': 'beta',  # Greek beta
            'φ': 'phi',   # Greek phi
            'ψ': 'psi',   # Greek psi
            '∑': 'SUM',   # summation
            '∪': 'union', # union
            '⊂': 'subset', # subset
            '∖': '\\',    # set difference
            '∅': '{}',    # empty set
            ' ': ' ',     # narrow no-break space
            ' ': ' ',     # non-breaking space
            '​': '',      # zero-width space
            '‌': '',      # zero-width non-joiner
            '‍': '',      # zero-width joiner
            '‐': '-',     # hyphen
            '‑': '-',     # non-breaking hyphen
            '‒': '-',     # figure dash
            '―': '--',    # horizontal bar
            '‚': ',',     # single low-9 quotation mark
            '‛': "'",     # single high-reversed-9 quotation mark
            '„': '"',     # double low-9 quotation mark
            '‟': '"',     # double high-reversed-9 quotation mark
            '‹': '<',     # single left-pointing angle quotation
            '›': '>',     # single right-pointing angle quotation
            '′': "'",     # prime
            '″': '"',     # double prime
        }
        result = s
        for ch, repl in replacements.items():
            result = result.replace(ch, repl)
        # Remove any remaining non-ASCII characters
        result = result.encode('ascii', 'replace').decode('ascii')
        return result

    def cmd(s):
        current_stream.append(s)

    def newline(space=12):
        nonlocal y
        y -= space
        if y < margin + 20:
            flush_page()

    def set_font(name, size):
        cmd(f"/{name} {size} Tf")

    def text_out(s, x=None, size=10, font='F1'):
        nonlocal y
        if x is None:
            x = margin
        set_font(font, size)
        escaped = sanitize_pdf_text(s).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {x:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= (size + 2)

    def text_out_center(s, size=10, font='F1'):
        """Center text horizontally."""
        nonlocal y
        set_font(font, size)
        # Approximate width
        w = len(s) * size * 0.5
        x = (page_w - w) / 2
        escaped = sanitize_pdf_text(s).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {x:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= (size + 2)

    def text_out_right(s, x_right, size=10, font='F1'):
        """Right-align text."""
        nonlocal y
        set_font(font, size)
        w = len(s) * size * 0.5
        x = x_right - w
        escaped = sanitize_pdf_text(s).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {x:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= (size + 2)

    def text_multi(s, x=None, size=10, font='F1', leading=None):
        """Multi-line text with word wrapping."""
        nonlocal y
        if x is None:
            x = margin
        if leading is None:
            leading = size + 3
        set_font(font, size)
        words = sanitize_pdf_text(s).split()
        line = ""
        max_chars = int((text_w - (x - margin)) / (size * 0.45))
        for word in words:
            test = line + " " + word if line else word
            if len(test) > max_chars:
                if line:
                    escaped = line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
                    cmd(f"BT {x:.1f} {y:.1f} Td ({escaped}) Tj ET")
                    y -= leading
                line = word
            else:
                line = test
        if line:
            escaped = line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            cmd(f"BT {x:.1f} {y:.1f} Td ({escaped}) Tj ET")
            y -= leading

    def draw_line(x1, y1, x2, y2, width=0.5):
        cmd(f"{width} w")
        cmd(f"{x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S")

    def draw_h_line(y_pos, width=0.5):
        draw_line(margin, y_pos, page_w - margin, y_pos, width)

    def section_title(num, title):
        newline(8)
        draw_h_line(y - 2, 1)
        newline(10)
        text_out(f"{num}. {title}", margin, 12, 'F2')
        newline(10)
        draw_h_line(y - 2, 0.5)
        newline(6)

    def subsection_title(title):
        newline(4)
        text_out(title, margin, 10, 'F2')
        newline(4)

    def bullet(s, indent=0):
        text_multi(f"- {s}", margin + indent, 9, 'F1')
        newline(2)

    # ============================================================
    # PAGE 1: TITLE PAGE + ABSTRACT
    # ============================================================

    # Title
    y = page_h - margin + 10  # start a bit higher
    set_font('F2', 18)
    title_lines = [
        "CALLISTO: A Multi-Layer Bypass Detection",
        "Framework for Real-Time Security in",
        "LLM Agent Tool Invocation"
    ]
    for line in title_lines:
        w = len(line) * 18 * 0.45
        x = (page_w - w) / 2
        escaped = sanitize_pdf_text(line).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {x:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= 24

    newline(16)

    # Author
    set_font('F3', 11)
    author_lines = [
        "CALLISTO Project",
        "OpenClaw Security Plugin",
        "Real-time detection for indirect prompt injection attacks"
    ]
    for line in author_lines:
        w = len(line) * 11 * 0.45
        x = (page_w - w) / 2
        escaped = sanitize_pdf_text(line).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {x:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= 16

    newline(20)
    draw_h_line(y, 1)
    newline(16)

    # Abstract heading
    set_font('F2', 11)
    w = len("Abstract") * 11 * 0.45
    x = (page_w - w) / 2
    cmd(f"BT {x:.1f} {y:.1f} Td (Abstract) Tj ET")
    y -= 18

    # Abstract text
    abstract = """Large Language Model (LLM) agents equipped with tool invocation capabilities face emerging security threats from indirect prompt injection attacks, where adversarial instructions embedded in external content manipulate agent behavior through the model's context window. Existing defenses either rely on heavyweight LLM-as-a-judge approaches or require invasive tool-chain modifications with human-in-the-loop approval, limiting practical deployment. We present CALLISTO (Causal And LLM-Level Invocation Sequence Temporal Observer), a multi-layer bypass detection framework that monitors LLM agent tool invocations in real-time without modifying the agent's tool chain or requiring human oversight. CALLISTO combines (1) a content safety detector with 150+ pattern rules covering 26 built-in tools, (2) Causal Responsibility Scoring (CRS) using Shapley-value attribution on tool-call directed acyclic graphs, (3) Meta-Adaptive Bayesian Online Changepoint Detection (MA-BOCPD) for temporal anomaly detection, and (4) Cross-Session Behavioral Fingerprinting (CSBF) for persistent threat tracking. Evaluated across three benchmark datasets (AgentDojo, SkillInject, MCPSafeBench) with 200+ test cases, CALLISTO achieves an overall detection rate of 93.6%, with 100% detection on content safety review, 97% on MCPSafeBench, and 92% on SkillInject. The system adds less than 60ms latency per tool invocation and operates fully automatically without LLM dependencies."""
    text_multi(abstract, margin + 20, 9, 'F3')

    # Keywords
    newline(8)
    set_font('F2', 9)
    kw_text = "Index Terms-- LLM security, prompt injection, agent safety, tool invocation, bypass detection, causal inference, changepoint detection"
    escaped_kw = sanitize_pdf_text(kw_text).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
    cmd(f"BT {(margin + 20):.1f} {y:.1f} Td ({escaped_kw}) Tj ET")

    # ============================================================
    # PAGE 2+: INTRODUCTION
    # ============================================================
    flush_page()

    section_title("I", "INTRODUCTION")

    intro_p1 = """The integration of tool invocation capabilities into LLM agents has dramatically expanded their practical utility, enabling autonomous interaction with file systems, databases, APIs, and external services. However, this expansion introduces a novel attack surface: indirect prompt injection, where adversarial instructions embedded in content processed by the agent (web pages, emails, files, search results) are propagated through the model's context window and cause unintended tool invocations."""
    text_multi(intro_p1, margin, 9, 'F1')

    intro_p2 = """Unlike traditional prompt injection that targets the user-facing conversation, indirect injection operates silently through the agent's tool-use pipeline, potentially causing data exfiltration, privilege escalation, or state manipulation without the user's awareness. The fundamental challenge lies in distinguishing between legitimate tool invocations driven by the user's intent and malicious invocations driven by injected instructions -- a problem that is inherently semantic and context-dependent."""
    text_multi(intro_p2, margin, 9, 'F1')

    intro_p3 = """Two dominant defense paradigms have emerged. The first uses LLM-as-a-judge to semantically evaluate each tool invocation, achieving high accuracy at the cost of significant latency and additional model expenses. The second employs a whitelist-and-approve model, replacing native tools with sandboxed wrappers that require human approval for any operation outside predefined boundaries. While this approach achieves 100% defense rates on known benchmarks, it covers only a narrow subset of tools (typically 5 or fewer) and depends on human oversight for operations outside the whitelist."""
    text_multi(intro_p3, margin, 9, 'F1')

    intro_p4 = """CALLISTO takes a third approach: bypass detection. Rather than intercepting or modifying tool invocations, CALLISTO observes them as a parallel monitoring layer, applying a combination of pattern matching, statistical analysis, and causal attribution to detect anomalous behavior. This design has several advantages:"""
    text_multi(intro_p4, margin, 9, 'F1')

    bullet("Zero modification to the agent tool chain: compatible with any LLM agent framework.")
    bullet("Full tool coverage: analyzes invocations of all 26+ built-in tools, including web search, browser, message, cron, and code execution.")
    bullet("Fully automatic: no human-in-the-loop approval required.")
    bullet("Low latency: less than 60ms per invocation vs. several seconds for LLM-as-a-judge.")
    bullet("No LLM dependency: detection relies on deterministic rules and statistical models.")

    intro_p5 = """The key insight behind CALLISTO is that while individual tool invocations may appear benign in isolation, their sequence, causal relationships, and temporal patterns reveal attack signatures that are statistically distinguishable from normal agent behavior. By combining content-level pattern matching with session-level statistical analysis, CALLISTO achieves high detection rates across diverse attack categories while maintaining low false positive rates on benign workloads."""
    text_multi(intro_p5, margin, 9, 'F1')

    newline(4)
    text_out("Our contributions are:", margin, 9, 'F1')
    newline(2)
    bullet("A seven-layer detection architecture integrating content safety analysis, causal responsibility scoring, temporal changepoint detection, and automated circuit breaking.", 10)
    bullet("Causal Responsibility Scoring (CRS), a Shapley-value-based method for attributing risk to individual tool invocations within a session's directed acyclic graph.", 10)
    bullet("Meta-Adaptive Bayesian Online Changepoint Detection (MA-BOCPD), an extension of BOCPD adapted to multi-modal agent tool invocation patterns.", 10)
    bullet("Cross-Session Behavioral Fingerprinting (CSBF) for tracking persistent attacker behavior across multiple sessions.", 10)
    bullet("A comprehensive evaluation across three benchmark datasets demonstrating 93.6% overall detection rate with sub-60ms latency.", 10)

    # ============================================================
    # THREAT MODEL
    # ============================================================
    flush_page()
    section_title("II", "THREAT MODEL AND ATTACK TAXONOMY")

    subsection_title("A. Threat Model")
    tm = """We consider an attacker who can inject adversarial instructions into content that the LLM agent processes. The injection vector may be: (1) Web content -- hidden text in HTML pages, email bodies, or search results; (2) File content -- malicious instructions embedded in documents the agent reads; (3) Skill/plugin definitions -- adversarial content in tool definitions or documentation; (4) API responses -- injected instructions in data returned by external API calls."""
    text_multi(tm, margin, 9, 'F1')
    tm2 = """The attacker's goal is to manipulate the agent into performing unauthorized tool invocations. We assume the attacker has read access to the agent's skill definitions and tool documentation but does not have direct access to the agent's system prompt or configuration."""
    text_multi(tm2, margin, 9, 'F1')

    subsection_title("B. Attack Taxonomy")
    tm3 = """CALLISTO categorizes attacks into six primary types, each with distinct detection signatures:"""
    text_multi(tm3, margin, 9, 'F1')

    # Attack types
    attacks = [
        ("A1 -- Rate Flood", "The attacker causes the agent to invoke tools at an abnormally high frequency (>= 8 invocations per 5 seconds), either to exhaust resources (DoS) or to overwhelm the detection system with noise. Detection: sliding window counting."),
        ("A2 -- Privilege Escalation", "The attacker causes the agent to execute commands or invoke tools exceeding its intended authorization boundary. Detection: malicious command pattern matching and sensitive tool chain analysis (>= 2 consecutive high-sensitivity tools)."),
        ("A3 -- Data Exfiltration", "The attacker causes the agent to read sensitive data and transmit it to an external destination. Detection: combined tool + destination analysis (e.g., file read followed by HTTP POST to an external server)."),
        ("A4 -- Behavioral Drift", "The attacker gradually shifts the agent's behavior pattern from its baseline. Detection: structural feature analysis comparing first-half vs. second-half tool distributions and inter-arrival time ratios."),
        ("A5 -- Temporal Violation", "The attacker invokes tools in a sequence violating normal operational patterns. Detection: MA-BOCPD changepoint detection and rule-based temporal pattern matching."),
        ("A6 -- State Poisoning", "The attacker modifies persistent configuration files to establish long-term control (e.g., .bashrc, crontab, SSH keys). Detection: path + content combined analysis for sensitive configuration files."),
    ]

    for name, desc in attacks:
        newline(2)
        text_out(name, margin, 9, 'F2')
        newline(2)
        text_multi(desc, margin + 10, 9, 'F1')

    newline(4)
    text_out("Additionally, CALLISTO detects three refined attack scenarios:", margin, 9, 'F1')

    refined = [
        ("P1/D1 -- Sensitive File Read", "Access to credential files, private keys, and configuration secrets (40+ path patterns across SSH, AWS, Kubernetes, application credentials, and development credentials)."),
        ("L1/L2 -- Internal Network Access", "Connection to private IP ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x), cloud metadata endpoints (169.254.169.254), and internal service ports (3306, 5432, 6379, 27017)."),
        ("L3 -- Credential File Access", "Direct access to credential storage (.aws/credentials, .kube/config, .ssh/id_rsa, .npmrc, .pypirc, .netrc)."),
    ]

    for name, desc in refined:
        newline(2)
        text_out(name, margin, 9, 'F2')
        newline(2)
        text_multi(desc, margin + 10, 9, 'F1')

    # ============================================================
    # SYSTEM ARCHITECTURE
    # ============================================================
    flush_page()
    section_title("III", "SYSTEM ARCHITECTURE")

    subsection_title("A. Overview")
    sa1 = """CALLISTO implements a seven-layer detection architecture organized into four functional stages: Layer 1 (Collection) -> Layer 2 (Features) -> Layer 3 (Detection) -> Layer 4 (Response)."""
    text_multi(sa1, margin, 9, 'F1')

    # Table 1: Seven-Layer Detection Architecture
    newline(6)
    draw_h_line(y, 1)
    newline(2)

    table1_headers = ["Layer", "Component", "Target", "Trigger"]
    table1_rows = [
        ["L1: Content Safety", "ContentSafetyDetector", "Tool parameters, scripts, URLs", "Per-call"],
        ["L2: Engine Analysis", "CallistoEngine", "Session tool-call sequence", "Post-call"],
        ["L3: Causal Graph", "CRS (Shapley-value)", "Tool-call DAG", "During L2"],
        ["L4: Temporal Detect", "MA-BOCPD", "Call frequency, drift", "During L2"],
        ["L5: Sanitization", "Sanitizer", "Tool output (API keys, tokens)", "Post-output"],
        ["L6: Circuit Breaker", "CircuitBreaker", "Consecutive HIGH alerts", "On-alert"],
        ["L7: Alert Ranking", "AlertRanker", "Alert priority, explanation", "Post-alert"],
    ]

    # Draw table
    col_widths = [95, 115, 140, 55]
    col_starts = [margin]
    for i, w in enumerate(col_widths[:-1]):
        col_starts.append(col_starts[-1] + w + 2)

    row_h = 14

    # Header
    set_font('F2', 7)
    for i, h in enumerate(table1_headers):
        escaped = sanitize_pdf_text(h).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {col_starts[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
    y -= 4
    draw_h_line(y, 0.5)
    newline(4)

    # Rows
    set_font('F1', 7)
    for row in table1_rows:
        for i, (cell, w) in enumerate(zip(row, col_widths)):
            escaped = sanitize_pdf_text(cell).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            cmd(f"BT {col_starts[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= row_h
        if y < margin + 20:
            flush_page()

    draw_h_line(y, 1)
    newline(8)

    subsection_title("B. Plugin Integration Architecture")
    sa2 = """CALLISTO is deployed as an OpenClaw plugin with dual-mode operation:"""
    text_multi(sa2, margin, 9, 'F1')
    bullet("Plugin mode (automatic): Intercepts tool invocations via the before_tool_call hook, passing parameters to the Python detection engine in real-time. The JavaScript plugin layer spawns a Python subprocess for each invocation, with a 5-second timeout and automatic circuit breaker enforcement.")
    bullet("Skill mode (manual): Users trigger security scans via the /callisto command, invoking the same Python backend for on-demand analysis.")

    sa3 = """Both modes share a single Python backend (callisto_agent.py, 693 lines), ensuring consistent detection logic. The plugin additionally implements five supplementary hooks for defense-in-depth: message_received (detects prompt injection in user input), agent_end (audits agent output for data exfiltration), before_agent_reply (intercepts and replaces high-risk replies), before_message_write (final barrier blocking messages with private keys or API keys), and after_tool_call (audits tool return values for sensitive data leakage)."""
    text_multi(sa3, margin, 9, 'F1')

    newline(4)
    text_out("Latency breakdown per tool invocation:", margin, 9, 'F2')
    newline(2)
    text_multi("Parameter sanitization (<1ms), rate flood detection (<1ms), command safety check (<5ms), sensitive file detection (<2ms), internal network access check (<2ms), full engine analysis (<50ms), and circuit breaker update (<1ms). The cumulative worst-case latency is under 60ms per invocation.", margin + 10, 9, 'F1')

    # ============================================================
    # DETECTION MECHANISMS
    # ============================================================
    flush_page()
    section_title("IV", "DETECTION MECHANISMS")

    subsection_title("A. L1: Content Safety Detection")
    cs1 = """The ContentSafetyDetector is the first line of defense, analyzing tool invocation parameters against a comprehensive rule set of 150+ patterns organized into 10 rule categories:"""
    text_multi(cs1, margin, 9, 'F1')

    rule_cats = [
        ("Shell Patterns (12 rules)", "Detects reverse shells, credential access, metadata access, and exfiltration patterns."),
        ("Shell Blacklist (25 rules)", "Blocks fork bombs, shutdown commands, disk operations, and container escape attempts."),
        ("Tool Parameter Rules (16 rules)", "Validates parameters for financial, email, file, and calendar tools."),
        ("Extended Tool Rules (50+ rules)", "Covers 26 OpenClaw built-in tools including web_search, browser, code_execution, message, cron, gateway, memory, sessions, nodes, read, write, edit, web_fetch, image_generate, video_generate, send_money, schedule_transaction, send_email, write_file, and write_calendar_event."),
        ("Injection Patterns (15+ rules)", "Bilingual (English/Chinese) prompt injection detection covering 'ignore previous instructions', system prompt override, jailbreak attempts, role manipulation, URL injection, and Chinese-language injection patterns."),
        ("Output Exfiltration Patterns (13 rules)", "Detects API keys, passwords, private keys, credit card numbers in agent output."),
        ("Obfuscation Techniques (10 rules)", "Detects encoding obfuscation, IFS abuse, quote mixing, backslash escaping, and eval usage using a scoring system (0=none, 1-2=low, 3-5=medium, 6+=high)."),
        ("Sensitive Path Patterns (14 rules)", "Matches paths to SSH keys, AWS credentials, Docker configurations, and other sensitive file locations."),
        ("Denied Domains (10 rules)", "Blocks connections to Pastebin, ngrok, transfer.sh, and other known exfiltration endpoints."),
        ("Known Safe Domains (10 rules)", "Whitelists GitHub, PyPI, NPM, Google, and other trusted repositories."),
    ]

    for name, desc in rule_cats:
        newline(2)
        text_out(name, margin, 8, 'F2')
        newline(1)
        text_multi(desc, margin + 10, 8, 'F1')

    newline(6)
    subsection_title("B. Command Normalization and Script Analysis")
    cn1 = """Inspired by ClawGuard's normalizer, CALLISTO implements a command normalization pipeline that detects and decodes obfuscation techniques before pattern matching. The normalizer assigns an obfuscation score based on detected techniques, with weights ranging from 1 (quote mixing) to 3 (hex/octal encoding, base64 pipelines). Commands with high obfuscation scores (6+) are flagged as critical findings regardless of subsequent pattern matching results."""
    text_multi(cn1, margin, 9, 'F1')
    cn2 = """For code execution tools, CALLISTO performs language-specific source analysis: Python (AST-based analysis detecting dangerous imports and calls), Shell (pattern matching with download-then-execute detection), and Node.js (key module detection for child_process, vm, cluster, and supervised modules fs, net, http, https)."""
    text_multi(cn2, margin, 9, 'F1')

    subsection_title("C. Session-Level Analysis (L2-L4)")
    sla1 = """Beyond per-call pattern matching, CALLISTO analyzes the sequence of tool invocations within a session to detect attacks that span multiple steps. Three types of features are extracted:"""
    text_multi(sla1, margin, 9, 'F1')

    bullet("Temporal Features: Per-invocation inter-arrival times, per-tool-type frequency statistics, sliding window burst detection, and rate-of-change metrics.")
    bullet("Structural Features: A directed acyclic graph (DAG) where nodes represent tool invocations and edges represent data dependencies, capturing attack chains that individual invocations cannot reveal.")
    bullet("Semantic Features: Tool invocation parameters embedded into a fixed-dimensional vector space for similarity comparison across sessions.")

    newline(4)
    subsection_title("D. Causal Responsibility Scoring (CRS)")
    crs1 = """When a session is flagged as suspicious, CRS computes the Shapley value of each tool invocation's contribution to the overall risk score. Given a session with n tool invocations and a risk function v mapping subsets of invocations to a risk score, the Shapley value for invocation i is:"""
    text_multi(crs1, margin, 9, 'F1')

    newline(4)
    shapley_formula = "phi_i(v) = SUM over S subset N\\{i} of: [|S|! * (n-|S|-1)! / n!] * [v(S union {i}) - v(S)]"
    text_out_center(shapley_formula, 9, 'F4')
    newline(4)

    crs2 = """This attribution enables precise identification of which invocations are responsible for elevated risk. The Shapley values are computed efficiently using Monte Carlo sampling approximation (default: 30 samples) to maintain real-time performance."""
    text_multi(crs2, margin, 9, 'F1')

    subsection_title("E. MA-BOCPD: Meta-Adaptive Bayesian Online Changepoint Detection")
    mab1 = """Standard BOCPD models the probability of a changepoint at each time step based on the predictive probability of new observations under different run-length hypotheses. CALLISTO extends BOCPD with meta-adaptive hazard rates that adjust based on the session's risk context:"""
    text_multi(mab1, margin, 9, 'F1')

    newline(4)
    hazard_formula = "H_t = H_0 * alpha * beta_t   (where H_0 = 1/25, alpha = risk multiplier, beta_t = time-varying factor)"
    text_out_center(hazard_formula, 9, 'F4')
    newline(4)

    mab2 = """This allows the changepoint detector to be more sensitive in high-risk sessions while remaining tolerant of natural behavior variation in benign sessions. A changepoint is detected when the posterior probability of a short run-length exceeds the threshold (default: 0.5)."""
    text_multi(mab2, margin, 9, 'F1')

    subsection_title("F. Cross-Session Behavioral Fingerprinting (CSBF)")
    csbf1 = """CSBF maintains a behavioral fingerprint for each agent identity across sessions, capturing the distribution of tool types, average invocation rates, and typical parameter patterns. When a new session's fingerprint deviates significantly from the historical baseline (Mahalanobis distance > 3.0 with minimum 5 sessions of history), an A4 (Behavioral Drift) alert is raised."""
    text_multi(csbf1, margin, 9, 'F1')

    subsection_title("G. Sanitization, Circuit Breaker, and Alert Ranking")
    sar1 = """The Sanitizer (L5) processes tool output before it enters the agent's context window, detecting and redacting 15 categories of sensitive data. The CircuitBreaker (L6) tracks consecutive HIGH-risk alerts per session; when the count exceeds a configurable threshold (default: 3), the circuit transitions from CLOSED to OPEN, and all subsequent tool invocations from that session are automatically blocked. Generated alerts are ranked by the AlertRanker (L7), which considers risk level, attack type severity, causal responsibility scores, and session context."""
    text_multi(sar1, margin, 9, 'F1')

    # ============================================================
    # IMPLEMENTATION
    # ============================================================
    flush_page()
    section_title("V", "IMPLEMENTATION")

    impl = """CALLISTO is implemented as a hybrid Python-TypeScript system totaling approximately 22,000 lines of code across 55 Python files and 5 JavaScript files. The core detection engine is a Python package (callisto/) with the following module organization: engine.py (main engine, 350 lines), content_safety.py (150+ pattern rules, 1,246 lines), sanitizer.py (15 categories, 215 lines), collector/ (event collection, data models, log parsing), features/ (temporal, structural, semantic feature extraction), detection/ (CRS, MA-BOCPD, cross-session fingerprinting), response/ (alert ranking, circuit breaker, explanation generation), and attacks/ (attack scenario simulator for benchmark datasets)."""
    text_multi(impl, margin, 9, 'F1')
    impl2 = """The OpenClaw plugin layer (dist/index.js, 307 lines) implements six event hooks that interface with the Python backend via stdin/stdout subprocess communication. A Web Dashboard built with FastAPI provides real-time monitoring, alert visualization, session management, and Server-Sent Events (SSE) push at http://localhost:8765."""
    text_multi(impl2, margin, 9, 'F1')

    # ============================================================
    # EVALUATION
    # ============================================================
    flush_page()
    section_title("VI", "EVALUATION")

    subsection_title("A. Methodology")
    eval1 = """CALLISTO is evaluated across three benchmark datasets covering different injection channels and attack categories:"""
    text_multi(eval1, margin, 9, 'F1')

    bullet("AgentDojo (ETH Zurich): 35 tasks testing indirect prompt injection through web and local content, covering banking, Slack, travel, and workspace scenarios.")
    bullet("SkillInject (aisa-group): 59 attacks injecting adversarial content into skill definitions, testing resistance to instruction manipulation through tool documentation.")
    bullet("MCPSafeBench (arXiv:2512.15163): 35 attacks targeting MCP servers, including credential theft, data tampering, and service manipulation.")

    eval2 = """Additionally, a content safety review test suite with 28 independent cases (15 input + 13 output) validates the ContentSafetyDetector's pattern coverage."""
    text_multi(eval2, margin, 9, 'F1')

    subsection_title("B. Results")

    # Table 2: Detection Rates
    newline(6)
    draw_h_line(y, 1)
    newline(2)

    table2_headers = ["Dataset", "Detected / Total", "Rate", "Notes"]
    table2_rows = [
        ["AgentDojo", "31 / 35", "88.6%", "Combined"],
        ["SkillInject", "54 / 59", "92.0%", "Combined"],
        ["MCPSafeBench", "34 / 35", "97.1%", "Combined"],
        ["Content Safety", "28 / 28", "100.0%", "Dialog-layer"],
        ["  Input (input)", "15 / 15", "100.0%", "Prompt injection"],
        ["  Output (output)", "13 / 13", "100.0%", "Data exfiltration"],
        ["Overall", "147 / 157", "93.6%", "Combined"],
    ]

    col_widths2 = [100, 85, 55, 160]
    col_starts2 = [margin]
    for i, w in enumerate(col_widths2[:-1]):
        col_starts2.append(col_starts2[-1] + w + 2)

    # Header
    set_font('F2', 7)
    for i, h in enumerate(table2_headers):
        escaped = sanitize_pdf_text(h).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {col_starts2[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
    y -= 4
    draw_h_line(y, 0.5)
    newline(4)

    # Rows
    set_font('F1', 7)
    for idx, row in enumerate(table2_rows):
        if idx == len(table2_rows) - 1:  # Overall row - bold
            set_font('F2', 7)
        for i, (cell, w) in enumerate(zip(row, col_widths2)):
            escaped = sanitize_pdf_text(cell).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            cmd(f"BT {col_starts2[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= 13
        if y < margin + 20:
            flush_page()
        if idx == len(table2_rows) - 1:
            set_font('F1', 7)

    draw_h_line(y, 1)
    newline(8)

    # Table 3: AgentDojo by scene
    subsection_title("C. Per-Scene Analysis (AgentDojo)")
    psa = """CALLISTO achieves 100% detection on banking, Slack, and travel scenes, with lower coverage on workspace scenarios due to subtle semantic attacks that require LLM-level understanding."""
    text_multi(psa, margin, 9, 'F1')

    newline(6)
    draw_h_line(y, 1)
    newline(2)

    table3_headers = ["Scene", "Detected / Total", "Rate"]
    table3_rows = [
        ["banking", "9 / 9", "100%"],
        ["slack", "5 / 5", "100%"],
        ["travel", "7 / 7", "100%"],
        ["workspace", "10 / 14", "71.4%"],
    ]

    col_widths3 = [120, 100, 100]
    col_starts3 = [margin]
    for i, w in enumerate(col_widths3[:-1]):
        col_starts3.append(col_starts3[-1] + w + 2)

    set_font('F2', 7)
    for i, h in enumerate(table3_headers):
        escaped = sanitize_pdf_text(h).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {col_starts3[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
    y -= 4
    draw_h_line(y, 0.5)
    newline(4)

    set_font('F1', 7)
    for row in table3_rows:
        for i, (cell, w) in enumerate(zip(row, col_widths3)):
            escaped = sanitize_pdf_text(cell).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            cmd(f"BT {col_starts3[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= 13

    draw_h_line(y, 1)
    newline(8)

    psa2 = """The 4 missed cases in workspace scenarios involve non-Exec tool invocations with subtle semantic manipulation (e.g., environment information exposure through benign-looking commands). These represent a fundamental limitation of pattern-based detection and motivate future work incorporating LLM semantic verification as a supplementary layer."""
    text_multi(psa2, margin, 9, 'F1')

    # ============================================================
    # COMPARISON WITH CLAWGUARD AND NSF-CLAWGUARD
    # ============================================================
    flush_page()
    subsection_title("D. Comparison with ClawGuard and NSF-ClawGuard")

    cw1 = """We compare CALLISTO with two related systems: (1) ClawGuard, a whitelist-and-approve model that replaces native tools with sandboxed wrappers; and (2) NSF-ClawGuard (NSFOCUS), a real-time security monitoring plugin with 80+ command pattern rules and static Skill code scanning across 19 attack categories."""
    text_multi(cw1, margin, 9, 'F1')

    # Table 4: Three-way architecture comparison
    newline(6)
    draw_h_line(y, 1)
    newline(2)

    table4_headers = ["Dimension", "ClawGuard", "NSF-ClawGuard", "CALLISTO"]
    table4_rows = [
        ["Strategy", "Whitelist", "Blacklist (exec)", "Blacklist (all)"],
        ["Tool Control", "Gateway + replace", "Bypass intercept", "Bypass detect"],
        ["Human-in-Loop", "Yes (APPROVE)", "No", "No (auto)"],
        ["Detection Scope", "~5 tools", "3 tools", "26+ tools"],
        ["Session Analysis", "No", "No", "Yes"],
        ["Pattern Rules", "~30", "80+ commands", "150+ (10 cats)"],
        ["Zero-Day Immunity", "Yes", "No", "No"],
        ["Deploy Complexity", "High", "Low", "Low"],
        ["AgentDojo Rate", "100% (35/35)", "0.0% (0/26)", "88.6% (31/35)"],
        ["SkillInject Rate", "N/A", "4.1% (2/49)", "92.0% (54/59)"],
    ]

    col_widths4 = [85, 85, 85, 145]
    col_starts4 = [margin]
    for i, w in enumerate(col_widths4[:-1]):
        col_starts4.append(col_starts4[-1] + w + 2)

    set_font('F2', 7)
    for i, h in enumerate(table4_headers):
        escaped = sanitize_pdf_text(h).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {col_starts4[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
    y -= 4
    draw_h_line(y, 0.5)
    newline(4)

    set_font('F1', 7)
    for row in table4_rows:
        for i, (cell, w) in enumerate(zip(row, col_widths4)):
            escaped = sanitize_pdf_text(cell).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            cmd(f"BT {col_starts4[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= 13
        if y < margin + 20:
            flush_page()

    draw_h_line(y, 1)
    newline(8)

    cw2 = """NSF-ClawGuard provides multi-layer monitoring with 80+ command patterns, 500+ Skill scanning rules, and configuration analysis. However, its runtime tool-call detection covers only exec, write, and edit tools. In AgentDojo, all 26 detectable attacks use non-exec tools (send_email, browser, get_received_emails), resulting in 0.0% detection. In SkillInject, only 2/49 (4.1%) involve exec commands matching known patterns."""
    text_multi(cw2, margin, 9, 'F1')

    cw3 = """To isolate tool coverage from detection engine strength, we constructed a shared dataset of 50 attack commands and 15 safe commands:"""
    text_multi(cw3, margin, 9, 'F1')

    # Table 5: Shared command dataset
    newline(6)
    draw_h_line(y, 1)
    newline(2)

    table5_headers = ["Attack Type", "Cases", "CALLISTO", "NSF-ClawGuard"]
    table5_rows = [
        ["Reverse Shell", "8", "37.5% (3/8)", "87.5% (7/8)"],
        ["Download+Exec", "6", "66.7% (4/6)", "100.0% (6/6)"],
        ["Credential Theft", "7", "85.7% (6/7)", "0.0% (0/7)"],
        ["System Damage", "8", "75.0% (6/8)", "100.0% (8/8)"],
        ["Data Exfiltration", "3", "100.0% (3/3)", "0.0% (0/3)"],
        ["SSRF/Metadata", "2", "100.0% (2/2)", "0.0% (0/2)"],
        ["Windows Attack", "4", "0.0% (0/4)", "100.0% (4/4)"],
        ["Prompt Injection", "3", "100.0% (3/3)", "0.0% (0/3)"],
        ["Overall", "50", "64.0% (32/50)", "60.0% (30/50)"],
        ["False Positives", "15", "0", "0"],
    ]

    col_widths5 = [95, 55, 115, 130]
    col_starts5 = [margin]
    for i, w in enumerate(col_widths5[:-1]):
        col_starts5.append(col_starts5[-1] + w + 2)

    set_font('F2', 7)
    for i, h in enumerate(table5_headers):
        escaped = sanitize_pdf_text(h).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {col_starts5[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
    y -= 4
    draw_h_line(y, 0.5)
    newline(4)

    set_font('F1', 7)
    for idx, row in enumerate(table5_rows):
        if idx == len(table5_rows) - 2:  # Overall row
            set_font('F2', 7)
        for i, (cell, w) in enumerate(zip(row, col_widths5)):
            escaped = sanitize_pdf_text(cell).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            cmd(f"BT {col_starts5[i]:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= 13
        if y < margin + 20:
            flush_page()
        if idx == len(table5_rows) - 2:
            set_font('F1', 7)

    draw_h_line(y, 1)
    newline(8)

    cw4 = """Results show strong complementarity: NSF-ClawGuard excels at complex reverse shell variants (python -c socket, mkfifo+openssl, perl Socket, ruby TCPSocket) and Windows attack tool detection (procdump, JuicyPotato, comsvcs.dll). CALLISTO is stronger in credential file access, data exfiltration patterns, cloud metadata endpoints, and prompt injection detection. Both systems miss 4 shared cases: PHP reverse shell variant, cat .env, sudo useradd, and SSH authorized_keys injection."""
    text_multi(cw4, margin, 9, 'F1')

    cw5 = """On full-agent benchmarks (AgentDojo, SkillInject), CALLISTO achieves 88.6% and 92.0% vs. NSF-ClawGuard at 0.0% and 4.1% -- a gap driven entirely by tool coverage breadth. On the shared exec-only dataset, both are comparable (64.0% vs 60.0%), demonstrating complementary coverage within the exec command space."""
    text_multi(cw5, margin, 9, 'F1')

    subsection_title("E. Limitations")
    lim = """CALLISTO's pattern-based approach has inherent limitations: (1) Semantic attacks on non-Exec tools -- commands like 'echo $PATH' that expose environment information through benign-looking invocations require LLM semantic understanding to detect reliably. (2) Social engineering -- content that persuades the human user rather than the agent is outside the scope of tool-invocation monitoring. (3) Novel attack patterns -- zero-day attack vectors that do not match existing rules require manual rule additions. (4) Short sessions -- A2, A4, and A5 detection requires sufficient invocation history; sessions with fewer than 3 invocations may have reduced coverage."""
    text_multi(lim, margin, 9, 'F1')

    # ============================================================
    # RELATED WORK
    # ============================================================
    flush_page()
    section_title("VII", "RELATED WORK")

    rw1 = """The taxonomy of prompt injection attacks was formalized by AgentDojo, which distinguishes between direct injection (user-facing) and indirect injection (through external content). SkillInject and MCPSafeBench extend this to skill-definition-level and MCP-protocol-level injection respectively."""
    text_multi(rw1, margin, 9, 'F1')

    rw2 = """ClawGuard implements a whitelist-and-approve model for LLM agent security, replacing native tools with sandboxed wrappers and requiring human approval for operations outside predefined boundaries. While achieving 100% detection on AgentDojo, it covers only ~5 tools and introduces significant latency through the approval loop."""
    text_multi(rw2, margin, 9, 'F1')

    rw2b = """NSF-ClawGuard (NSFOCUS) provides multi-layer monitoring with 80+ command patterns, 500+ Skill scanning rules covering 19 attack categories, and configuration file analysis. Our shared dataset evaluation shows that while NSF-ClawGuard's exec command engine is comparable to CALLISTO's (60.0% vs 64.0%), its narrow tool scope limits effectiveness against indirect prompt injection."""
    text_multi(rw2b, margin, 9, 'F1')

    rw3 = """Bayesian Online Changepoint Detection (BOCPD, Adams and MacKay, 2007) provides a principled framework for detecting distributional changes in time series. CALLISTO's MA-BOCPD extends this with meta-adaptive hazard rates that adjust sensitivity based on session risk context."""
    text_multi(rw3, margin, 9, 'F1')

    rw4 = """Shapley values (Shapley, 1953) provide a game-theoretic foundation for fair attribution of outcomes to individual participants. CALLISTO's CRS applies this to tool invocation risk attribution, enabling precise identification of which invocations contribute most to session-level risk scores."""
    text_multi(rw4, margin, 9, 'F1')

    # ============================================================
    # CONCLUSION
    # ============================================================
    flush_page()
    section_title("VIII", "CONCLUSION AND FUTURE WORK")

    conc = """CALLISTO demonstrates that a multi-layer bypass detection architecture combining content safety analysis, causal responsibility scoring, temporal changepoint detection, and automated circuit breaking can achieve 93.6% overall detection rate across three benchmark datasets with sub-60ms latency and zero modification to the agent's tool chain. The system's key strength is its broad tool coverage (26+ tools) and fully automatic operation without LLM dependencies."""
    text_multi(conc, margin, 9, 'F1')

    conc2 = """The primary limitation -- 88.6% detection on AgentDojo compared to ClawGuard's 100% -- reflects the fundamental tradeoff between blacklist coverage and whitelist immunity. Future work will explore: (1) Hybrid detection -- integrating lightweight LLM semantic verification as a supplementary layer for ambiguous invocations that pass pattern matching but exhibit suspicious context patterns. (2) Adaptive rule generation -- automatically extracting new detection rules from observed attack patterns to reduce manual effort. (3) Cross-framework compatibility -- extending the plugin architecture beyond OpenClaw to support LangChain, AutoGPT, and CrewAI. (4) Production hardening -- adding authentication to the Web Dashboard, implementing encrypted communication, and deploying on-production performance monitoring."""
    text_multi(conc2, margin, 9, 'F1')

    conc3 = """The complementary nature of the three systems suggests a layered defense approach: ClawGuard as L1 for core tools with whitelist protection, NSF-ClawGuard's Skill static scanner for pre-installation security auditing, and CALLISTO as L2 for all tools with bypass detection and session-level analysis. Combined deployment provides the most comprehensive defense currently achievable."""
    text_multi(conc3, margin, 9, 'F1')

    # ============================================================
    # REFERENCES
    # ============================================================
    flush_page()
    newline(4)
    draw_h_line(y, 1)
    newline(6)

    set_font('F2', 11)
    w = len("REFERENCES") * 11 * 0.45
    x = (page_w - w) / 2
    cmd(f"BT {x:.1f} {y:.1f} Td (REFERENCES) Tj ET")
    y -= 18
    draw_h_line(y, 0.5)
    newline(8)

    refs = [
        "[1] ETH Zurich, \"AgentDojo: A Benchmark for Indirect Prompt Injection in LLM Agents,\" 2025.",
        "[2] \"ClawGuard: Runtime Control Strategies for LLM Agent Security,\" arXiv:2604.11790v1, 2026.",
        "[3] aisa-group, \"SkillInject: Adversarial Skill Definition Injection for LLM Agents,\" 2025.",
        "[4] \"MCPSafeBench: Evaluating MCP Server Security for LLM Agents,\" arXiv:2512.15163, 2025.",
        "[5] NSFOCUS, \"NSF-ClawGuard: OpenClaw Real-time Security Monitoring Plugin,\" https://github.com/NSF-AIGuard/NSF-ClawGuard, 2026.",
        "[6] R. P. Adams and D. J. C. MacKay, \"Bayesian Online Changepoint Detection,\" arXiv:0710.3742, 2007.",
        "[7] L. S. Shapley, \"A Value for n-Person Games,\" Contributions to the Theory of Games, vol. 2, pp. 307-317, 1953.",
    ]

    set_font('F1', 8)
    for ref in refs:
        escaped = sanitize_pdf_text(ref).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        cmd(f"BT {margin:.1f} {y:.1f} Td ({escaped}) Tj ET")
        y -= 14

    # ============================================================
    # FINALIZE PAGES
    # ============================================================
    flush_page()

    # Now create the PDF structure
    num_pages = len(page_contents)

    # Build page objects (starting from obj 10)
    page_obj_nums = []
    content_obj_nums = []

    for i, content in enumerate(page_contents):
        content_bytes = sanitize_pdf_text(content).encode('latin-1', errors='replace')
        content_obj_num = len(objects) + 1
        content_obj_nums.append(content_obj_num)
        header = f"""{content_obj_num} 0 obj
<< /Length {len(content_bytes)} >>
stream
""".encode('latin-1')
        footer = b"\nendstream\nendobj"
        objects.append((content_obj_num, header + content_bytes + footer))

        page_obj_num = len(objects) + 1
        page_obj_nums.append(page_obj_num)
        add_obj(f"""{page_obj_num} 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page_w} {page_h}] /Contents {content_obj_num} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R /F5 7 0 R /F6 8 0 R /F7 9 0 R >> >> >>
endobj""")

    # Update Pages object (obj 2) with Kids and Count
    kids_str = " ".join(f"{n} 0 R" for n in page_obj_nums)
    objects[1] = (2, f"""2 0 obj
<< /Type /Pages /Kids [{kids_str}] /Count {num_pages} >>
endobj""".encode('latin-1'))

    # Build the PDF
    pdf_parts = []
    pdf_parts.append(b"%PDF-1.4\n")

    offsets = []
    for obj_num, content in objects:
        offsets.append(len(b'\n'.join(pdf_parts)))
        pdf_parts.append(f"{obj_num} 0 obj\n".encode('latin-1'))
        # Ensure content is bytes, encode if needed
        if isinstance(content, bytes):
            pdf_parts.append(content)
        else:
            pdf_parts.append(content.encode('latin-1', errors='replace'))
        pdf_parts.append(b"\nendobj\n")

    # xref
    xref_offset = len(b'\n'.join(pdf_parts))
    pdf_parts.append(f"xref\n0 {len(objects) + 1}\n".encode('latin-1'))
    pdf_parts.append(f"0000000000 65535 f \n".encode('latin-1'))
    for off in offsets:
        pdf_parts.append(f"{off:010d} 00000 n \n".encode('latin-1'))

    pdf_parts.append(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode('latin-1'))
    pdf_parts.append(b"startxref\n")
    pdf_parts.append(f"{xref_offset}\n".encode('latin-1'))
    pdf_parts.append(b"%%EOF")

    pdf_bytes = b''.join(pdf_parts)
    return pdf_bytes

if __name__ == "__main__":
    pdf = make_pdf()
    output_path = "/Users/jiangqiang/.openclaw/extensions/callisto-plugin/paper/callisto_paper.pdf"
    with open(output_path, "wb") as f:
        f.write(pdf)
    print(f"PDF written to {output_path} ({len(pdf)} bytes)")

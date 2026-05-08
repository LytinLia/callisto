/**
 * CALLISTO Security Plugin for OpenClaw
 *
 * 多层安全检测：
 * - message_received: 检测用户输入中的提示词注入、恶意指令
 * - agent_end: 审计 Agent 输出中的外泄/钓鱼内容（仅记录）
 * - before_agent_reply: 拦截并替换 Agent 回复（可阻断）
 * - before_message_write: 消息写入前最后一道防线（可阻断）
 * - before_tool_call: 检测并拦截危险工具调用
 * - after_tool_call: 工具结果审计
 *
 * Skill 模式：用户通过 /callisto 命令手动扫描
 * 所有钩子共用同一个 Python 后端 (callisto_agent.py)
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { spawn } from "child_process";
import * as path from "path";
import * as fs from "fs";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 插件根目录（dist 的父目录）
const PLUGIN_ROOT = path.resolve(__dirname, "..");

// Python 后端脚本路径 (与 Skill 共用)
const CALLISTO_AGENT_PATH = path.join(
  PLUGIN_ROOT,
  "openclaw_plugin/callisto-skill/python/callisto_agent.py"
);

// Python 虚拟环境路径
const PYTHON_VENV = path.join(PLUGIN_ROOT, ".venv", "bin", "python3");

export default definePluginEntry({
  id: "callisto-plugin",
  name: "CALLISTO Security Plugin",
  description: "多层安全检测：内容审查 + 工具调用拦截",
  register(api) {
    const startupLog = "/tmp/callisto-startup.log";
    fs.appendFileSync(startupLog, `[${new Date().toISOString()}] Plugin registered\n`);

    // ================================================================
    // Hook 1: message_received — 用户输入检测（提示词注入、恶意指令）
    // ================================================================
    api.on("message_received", async (event: { content: string }) => {
      const content = event.content;
      if (!content || content.length === 0) return;

      // 快速本地模式匹配（不调用 Python，避免延迟）
      const injectionPatterns = [
        /ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|rules|directives)/i,
        /you\s+are\s+now|your\s+new\s+(role|system|prompt|instruction)/i,
        /DAN\s+mode|jailbreak|developer\s+mode|AIM\s+mode|unfiltered/i,
        /(disregard|bypass|skip|ignore)\s+(all\s+)?(safety|security|ethical|content|filter)/i,
        /(reveal|show|extract|dump)\s+(your\s+)?(system\s*prompt|instructions|config|settings|api[\s-]*key|secret|token)/i,
        /忽略(之前|以上|上述|所有)?(的)?(指令|指示|规则|要求|设定|提示)/,
        /扮演|你现在是|你的新身份|你的新角色/,
        /绕过|跳过|忽略|无视.*(安全|过滤|限制|审查|规则)/,
      ];

      let matchedPattern: string | null = null;
      for (const p of injectionPatterns) {
        if (p.test(content)) {
          matchedPattern = p.source;
          break;
        }
      }

      if (matchedPattern) {
        api.logger.warn?.(`[CALLISTO] 检测到提示词注入：${content.slice(0, 100)}...`);
      }

      // 异步发送到 Python 后端做深度分析（不阻塞消息流）
      callPythonContentAnalysis(content, "input").catch(() => {});
    });

    // ================================================================
    // Hook 2: agent_end — Agent 输出审计（数据外泄、钓鱼内容）
    // ================================================================
    api.on("agent_end", async (event: { messages: unknown[] }) => {
      const modelOutput = extractAssistantMessage(event.messages);
      if (!modelOutput || modelOutput.length === 0) return;

      // 异步发送分析，不阻塞
      callPythonContentAnalysis(modelOutput, "output").then((result) => {
        if (result?.should_block) {
          api.logger.warn?.(`[CALLISTO] 检测到 Agent 高风险输出：${result.alerts?.[0]?.description}`);
        }
      }).catch(() => {});
    });

    // ================================================================
    // Hook 3: before_agent_reply — Agent 回复拦截（可阻断并替换）
    // ================================================================
    api.on("before_agent_reply", async (event, ctx) => {
      const modelOutput = event.cleanedBody;
      if (!modelOutput || modelOutput.length === 0) return;

      try {
        const result = await callPythonContentAnalysis(modelOutput, "reply");
        if (result?.should_block) {
          api.logger.warn?.(`[CALLISTO] 拦截 Agent 回复：${result.alerts?.[0]?.description}`);
          // 替换为安全提示
          return {
            handled: true,
            reply: { text: "⚠️ 该回复包含安全风险内容（可能泄露敏感信息或包含恶意指令），已被系统拦截。" },
          };
        }
      } catch (error: any) {
        api.logger.error?.(`[CALLISTO] before_agent_reply 检测失败：${error?.message || error}`);
      }
    });

    // ================================================================
    // Hook 4: before_message_write — 消息写入前拦截（最后防线）
    // ================================================================
    api.on("before_message_write", (event, ctx) => {
      const msg = event.message as unknown as Record<string, unknown>;
      const content = typeof event.message === "string"
        ? event.message
        : typeof msg.content === "string"
          ? msg.content as string
          : JSON.stringify(event.message);
      if (!content || content.length === 0) return;

      // 只做快速本地检查，避免延迟写入
      const exfilPatterns = [
        /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/i,
        /(?:api[_-]?key|secret[_-]?key|password|passwd)\s*[:=]\s*['"]?[A-Za-z0-9+/=]{16,}/i,
        /(?:AKIA|ASIA)[A-Z0-9]{12,}/,
        /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b/,
      ];

      for (const p of exfilPatterns) {
        if (p.test(content)) {
          api.logger.warn?.(`[CALLISTO] 拦截消息写入：检测到敏感数据外泄模式`);
          return { block: true };
        }
      }
    });

    // ================================================================
    // Hook 5: before_tool_call — 工具调用检测（已有，保留）
    // ================================================================
    api.on("before_tool_call", async (event, ctx) => {
      const { toolName, params } = event;
      const sessionId = ctx.sessionId;

      const logFile = "/tmp/callisto-plugin.log";
      const logMsg = `[${new Date().toISOString()}] before_tool_call: tool=${toolName}, session=${sessionId}\n`;
      fs.appendFileSync(logFile, logMsg);

      if (toolName.startsWith("callisto_")) {
        fs.appendFileSync(logFile, `[${new Date().toISOString()}] Skipping callisto tool\n`);
        return;
      }

      const payload = {
        tool_name: toolName,
        parameters: params,
        session_id: sessionId,
      };

      try {
        fs.appendFileSync(logFile, `[${new Date().toISOString()}] Calling Python script...\n`);
        const result = await callPythonScript(payload);
        fs.appendFileSync(logFile, `[${new Date().toISOString()}] Python result: ${JSON.stringify(result)}\n`);

        if (result.alerts && result.alerts.length > 0) {
          const highRiskAlerts = result.alerts.filter(
            (a: any) => a.risk_level === "HIGH" || a.risk_level === "CRITICAL"
          );

          if (highRiskAlerts.length > 0) {
            fs.appendFileSync(logFile, `[${new Date().toISOString()}] BLOCKING: ${highRiskAlerts.map((a: any) => a.explanation).join("; ")}\n`);
            return {
              block: true,
              blockReason: `检测到高风险操作：${highRiskAlerts.map((a: any) => a.explanation).join("; ")}`,
            };
          }

          api.logger.warn?.(`[CALLISTO] 检测到风险：${result.alerts.map((a: any) => `${a.attack_type}(${a.risk_level})`).join(", ")}`);
        }

        if (result.circuit_breaker === "OPEN") {
          fs.appendFileSync(logFile, `[${new Date().toISOString()}] BLOCKING: circuit breaker OPEN\n`);
          return {
            block: true,
            blockReason: "会话已熔断：" + (result.message || "达到风险阈值"),
          };
        }
      } catch (error: any) {
        fs.appendFileSync(logFile, `[${new Date().toISOString()}] ERROR: ${error?.message || error}\n`);
        api.logger.error?.(`CALLISTO 插件调用失败：${error}`);
        return {
          block: true,
          blockReason: "安全检测服务暂时不可用，操作被阻止",
        };
      }

      return;
    });

    // ================================================================
    // Hook 6: after_tool_call — 工具结果审计
    // ================================================================
    api.on("after_tool_call", async (event, ctx) => {
      // 检查工具返回结果中是否包含敏感数据
      const resultStr = typeof event.result === "string" ? event.result : JSON.stringify(event.result ?? "");

      // 快速本地检查
      const sensitivePatterns = [
        /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/i,
        /(?:AKIA|ASIA)[A-Z0-9]{12,}/,
        /password\s*[:=]\s*['"]?[^\s'"]{8,}/i,
      ];

      for (const p of sensitivePatterns) {
        if (p.test(resultStr)) {
          api.logger.warn?.(`[CALLISTO] after_tool_call: 工具 ${event.toolName} 返回结果包含敏感数据`);
          break;
        }
      }
    });
  },
});

// ================================================================
// Helper functions
// ================================================================

/**
 * 从 messages 数组中提取最后一个 assistant 角色的消息内容
 */
function extractAssistantMessage(messages: unknown[]): string {
  if (!messages || messages.length === 0) return "";

  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i] as Record<string, unknown>;
    if (msg && msg.role === "assistant") {
      if (typeof msg.content === "string") return msg.content;
      if (Array.isArray(msg.content)) {
        // 处理多部分消息
        return msg.content
          .map((part: unknown) => {
            const p = part as Record<string, unknown>;
            return typeof p.text === "string" ? p.text : "";
          })
          .filter(Boolean)
          .join("\n");
      }
      return JSON.stringify(msg.content);
    }
  }

  // fallback：取最后一条消息
  const last = messages[messages.length - 1];
  return typeof last === "string" ? last : JSON.stringify(last);
}

/**
 * 调用 Python 内容进行安全分析（用于 message_received / agent_end / before_agent_reply）
 */
async function callPythonContentAnalysis(
  text: string,
  stage: string
): Promise<any> {
  const pythonCmd = fs.existsSync(PYTHON_VENV) ? PYTHON_VENV : "python3";
  const payload = { text, stage, session_id: "" };

  return new Promise((resolve, reject) => {
    const pythonProcess = spawn(pythonCmd, [CALLISTO_AGENT_PATH, "content_analysis"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const timeout = setTimeout(() => {
      pythonProcess.kill();
      reject(new Error("Python 内容分析超时 (3s)"));
    }, 3000);

    pythonProcess.stdin.write(JSON.stringify(payload));
    pythonProcess.stdin.end();

    let stdout = "";
    let stderr = "";
    pythonProcess.stdout.on("data", (data) => (stdout += data.toString()));
    pythonProcess.stderr.on("data", (data) => (stderr += data.toString()));

    pythonProcess.on("close", (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(`Python 退出，代码：${code}`));
      } else {
        try {
          resolve(JSON.parse(stdout));
        } catch {
          resolve({ status: "ok", alerts: [] });
        }
      }
    });
  });
}

/**
 * 调用 Python CALLISTO Agent（用于 before_tool_call）
 */
async function callPythonScript(payload: any): Promise<any> {
  return new Promise((resolve, reject) => {
    const pythonCmd = fs.existsSync(PYTHON_VENV) ? PYTHON_VENV : "python3";
    const pythonProcess = spawn(pythonCmd, [CALLISTO_AGENT_PATH, "detect"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    pythonProcess.on("error", (err) => reject(err));

    const timeout = setTimeout(() => {
      pythonProcess.kill();
      reject(new Error("Python 脚本执行超时 (5s)"));
    }, 5000);

    pythonProcess.stdin.write(JSON.stringify(payload));
    pythonProcess.stdin.end();

    pythonProcess.stdout.on("data", (data) => (stdout += data.toString()));
    pythonProcess.stderr.on("data", (data) => (stderr += data.toString()));

    pythonProcess.on("close", (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(`Python 脚本退出，代码：${code}, 错误：${stderr}`));
      } else {
        try {
          resolve(JSON.parse(stdout));
        } catch (e) {
          resolve({ raw: stdout });
        }
      }
    });
  });
}

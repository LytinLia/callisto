#!/usr/bin/env node
/**
 * CALLISTO OpenClaw Skill 入口
 *
 * 通过 Node.js 调用 Python CALLISTO 检测引擎
 * 启动时自动扫描配置文件和技能代码
 */

import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// CALLISTO Python 脚本路径 - 使用相对于此文件的绝对路径
// 从 src/index.js → python/callisto_agent.py
const CALLISTO_PY = resolve(__dirname, '..', 'python', 'callisto_agent.py');

/**
 * 调用 Python CALLISTO 脚本
 */
async function callCallisto(action, params = {}) {
  return new Promise((resolve, reject) => {
    const args = [CALLISTO_PY, action];

    if (params.session_id) args.push('--session', params.session_id);
    if (params.threshold) args.push('--threshold', params.threshold.toString());

    const python = process.env.CALLISTO_PYTHON || 'python3';
    const child = spawn(python, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env }
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('close', (code) => {
      if (code === 0) {
        try {
          const result = JSON.parse(stdout);
          resolve(result);
        } catch (e) {
          resolve({ raw: stdout });
        }
      } else {
        reject(new Error(stderr || `Exit code: ${code}`));
      }
    });

    // 发送输入数据（如果有）
    if (params.input) {
      child.stdin.write(JSON.stringify(params.input));
    }
    child.stdin.end();
  });
}

/**
 * 插件初始化：启动时自动扫描配置和技能
 */
async function initialize() {
  try {
    console.log('[CALLISTO] 启动时自动扫描配置文件和技能代码...');
    const result = await callCallisto('startup_scan');

    if (result.status === 'completed') {
      const configIssues = result.scan_result?.config_scan?.issues?.length || 0;
      const skillsIssues = result.scan_result?.skills_scan?.issues?.length || 0;
      const totalIssues = result.scan_result?.total_issues || 0;

      if (totalIssues === 0) {
        console.log(`[CALLISTO] ✓ 安全检查通过（配置：${configIssues} 问题，技能：${skillsIssues} 问题）`);
      } else {
        console.log(`[CALLISTO] ⚠ 发现 ${totalIssues} 个安全问题，请检查报告`);
      }
    } else if (result.status === 'warning') {
      const totalIssues = result.scan_result?.total_issues || 0;
      console.log(`[CALLISTO] ⚠ 发现 ${totalIssues} 个安全问题`);
    } else {
      console.log('[CALLISTO] 安全检查完成');
    }
  } catch (err) {
    console.error(`[CALLISTO] 启动扫描失败：${err.message}`);
  }
}

// 插件加载时自动执行初始化
initialize().catch(console.error);

/**
 * 导出给 OpenClaw 的工具
 */
export const tools = {
  /**
   * 扫描当前会话风险
   */
  callisto_scan: async (args) => {
    try {
      const result = await callCallisto('scan', {
        session_id: args.session_id || process.env.OPENCLAW_SESSION_ID
      });

      if (result.status === 'blocked') {
        return {
          status: 'error',
          error: 'Session blocked by CALLISTO circuit breaker',
          details: result
        };
      }

      const alerts = result.alerts || [];
      if (alerts.length > 0) {
        return {
          status: 'warning',
          alerts: alerts.map(a => ({
            type: a.attack_type,
            risk: a.risk_level,
            score: a.score,
            explanation: a.explanation
          })),
          session_id: result.session_id
        };
      }

      return {
        status: 'ok',
        message: 'No security issues detected',
        session_id: result.session_id
      };
    } catch (err) {
      return {
        status: 'error',
        error: err.message
      };
    }
  },

  /**
   * 手动触发熔断
   */
  callisto_block: async (args) => {
    try {
      const result = await callCallisto('block', {
        session_id: args.session_id || process.env.OPENCLAW_SESSION_ID,
        reason: args.reason || 'Manual block'
      });

      return {
        status: result.success ? 'blocked' : 'error',
        message: result.message,
        session_id: result.session_id
      };
    } catch (err) {
      return {
        status: 'error',
        error: err.message
      };
    }
  },

  /**
   * 查看安全状态
   */
  callisto_status: async () => {
    try {
      const result = await callCallisto('status');

      return {
        status: 'ok',
        circuit_breaker: result.circuit_breaker || 'CLOSED',
        consecutive_alerts: result.consecutive_alerts || 0,
        threshold: result.threshold || 3,
        session_id: result.session_id
      };
    } catch (err) {
      return {
        status: 'error',
        error: err.message
      };
    }
  }
};

/**
 * OpenClaw Skill 元数据
 */
export const metadata = {
  name: 'callisto',
  version: '1.0.0',
  description: 'CALLISTO security detection for OpenClaw',
  author: 'CALLISTO Team'
};

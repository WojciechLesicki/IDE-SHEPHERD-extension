import * as fs from 'fs';
import * as path from 'path';
import { FS_RULES, FsRule, FsRuleType } from '../../detection/fs-rules';

/** Hook script names targeted by the DPRK Contagious Interview / git-hooks campaign. */
export const HOOK_SCRIPT_NAMES = ['pre-commit', 'post-checkout'] as const;

export const GIT_HOOK_MALICIOUS_RULE_ID = 'write_git_hooks_malicious';

/** Network download primitive in a hook script. */
const GIT_HOOK_DOWNLOADER_PATTERN = /\b(curl|wget|Invoke-WebRequest)\b/i;

/** Pipe-to-shell execution (Contagious Interview TTP). */
const GIT_HOOK_PIPE_TO_SHELL_PATTERN = /\|\s*(sh|bash|zsh|cmd)\b|powershell\s+-/i;

/** Known campaign C2 host in hook file content. */
const GIT_HOOK_KNOWN_C2_PATTERN = /precommit\.vercel\.app/i;

/**
 * Dual-signal content check for malicious git hooks (reduces FP vs curl-only docs).
 * Matches when (downloader + pipe-to-shell) OR known campaign C2 host is present.
 */
export function isMaliciousGitHookContent(content: string): boolean {
  if (GIT_HOOK_KNOWN_C2_PATTERN.test(content)) {
    return true;
  }
  return GIT_HOOK_DOWNLOADER_PATTERN.test(content) && GIT_HOOK_PIPE_TO_SHELL_PATTERN.test(content);
}

export interface HookScanMatch {
  filePath: string;
  rule: FsRule;
  content: string;
}

/**
 * Match file path + content against git-hook and git-config FS rules.
 * Used by static workspace scan and WorkspaceWatcher.
 */
export function matchHookFile(filePath: string, content: string): HookScanMatch | null {
  const normalizedPath = filePath.replace(/\\/g, '/');

  for (const rule of FS_RULES) {
    if (rule.type !== FsRuleType.WRITE) {
      continue;
    }
    if (!rule.operations.includes('write')) {
      continue;
    }
    if (!rule.pathPattern.test(normalizedPath)) {
      continue;
    }
    if (rule.id === GIT_HOOK_MALICIOUS_RULE_ID) {
      if (!isMaliciousGitHookContent(content)) {
        continue;
      }
    } else {
      if (!rule.contentPattern) {
        continue;
      }
      if (!rule.contentPattern.test(content)) {
        continue;
      }
    }

    return { filePath, rule, content };
  }

  return null;
}

/** Parse `core.hooksPath` from a .git/config file (returns relative or absolute path). */
export function parseCoreHooksPath(configContent: string): string | null {
  const match = /hookspath\s*=\s*(\S+)/i.exec(configContent);
  if (!match) {
    return null;
  }

  let value = match[1].trim();
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    value = value.slice(1, -1);
  }

  return value || null;
}

function listHookFilesInDir(dirPath: string): string[] {
  if (!fs.existsSync(dirPath)) {
    return [];
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(dirPath);
  } catch {
    return [];
  }

  if (!stat.isDirectory()) {
    return [];
  }

  const files: string[] = [];
  for (const name of fs.readdirSync(dirPath)) {
    if (name.endsWith('.sample')) {
      continue;
    }
    if (!(HOOK_SCRIPT_NAMES as readonly string[]).includes(name)) {
      continue;
    }
    const filePath = path.join(dirPath, name);
    try {
      if (fs.statSync(filePath).isFile()) {
        files.push(filePath);
      }
    } catch {
      // skip unreadable entries
    }
  }

  return files;
}

/**
 * Collect absolute paths to scan under a workspace root:
 * standard hook dirs, custom core.hooksPath, and .git/config.
 */
export function collectScanTargets(workspaceRoot: string): string[] {
  const targets = new Set<string>();

  const gitConfigPath = path.join(workspaceRoot, '.git', 'config');
  if (fs.existsSync(gitConfigPath)) {
    targets.add(gitConfigPath);
  }

  const standardHookDirs = [
    path.join(workspaceRoot, '.husky'),
    path.join(workspaceRoot, '.githooks'),
    path.join(workspaceRoot, '.git', 'hooks'),
  ];

  for (const dir of standardHookDirs) {
    for (const filePath of listHookFilesInDir(dir)) {
      targets.add(filePath);
    }
  }

  if (fs.existsSync(gitConfigPath)) {
    try {
      const configContent = fs.readFileSync(gitConfigPath, 'utf8');
      const hooksPath = parseCoreHooksPath(configContent);
      if (hooksPath) {
        const customDir = path.isAbsolute(hooksPath) ? hooksPath : path.join(workspaceRoot, hooksPath);
        for (const filePath of listHookFilesInDir(customDir)) {
          targets.add(filePath);
        }
      }
    } catch {
      // unreadable config — other targets still scanned
    }
  }

  return [...targets];
}

/** Static on-activation scan of all hook-related paths in a workspace folder. */
export function scanWorkspaceRoot(workspaceRoot: string): HookScanMatch[] {
  const matches: HookScanMatch[] = [];

  for (const filePath of collectScanTargets(workspaceRoot)) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }

    const match = matchHookFile(filePath, content);
    if (match) {
      matches.push(match);
    }
  }

  return matches;
}

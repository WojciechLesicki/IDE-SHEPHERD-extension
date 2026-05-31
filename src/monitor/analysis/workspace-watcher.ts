import * as path from 'path';
import * as vscode from 'vscode';
import * as fs from 'fs';
import { Logger } from '../../lib/logger';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { NotificationService } from '../../lib/services/notification-service';
import { TrustedWorkspaceService } from '../../lib/services/trusted-workspace-service';
import { SecurityEvent, IoC } from '../../lib/events/sec-events';
import { FsEvent } from '../../lib/events/fs-events';
import { WorkspaceInfo, ExtensionInfo } from '../../lib/events/ext-events';
import { HookScanMatch, matchHookFile, scanWorkspaceRoot } from './hook-scanner';
import { GitHookAlertDedup } from './git-hook-alert-dedup';

export class WorkspaceWatcher {
  private static watchers: vscode.FileSystemWatcher[] = [];
  private static extensionMode: vscode.ExtensionMode = vscode.ExtensionMode.Production;

  /** Runtime opt-in from Settings (`ide-shepherd.gitHookAdvisory.enabled`, default false). */
  static isGitHookAdvisoryEnabled(): boolean {
    return vscode.workspace.getConfiguration('ide-shepherd.gitHookAdvisory').get<boolean>('enabled') ?? false;
  }

  public static activate(context: vscode.ExtensionContext): void {
    this.extensionMode = context.extensionMode;

    if (!this.isGitHookAdvisoryEnabled()) {
      Logger.info('Workspace Watcher: git-hook advisory disabled (gitHookAdvisory.enabled=false)');
      return;
    }

    Logger.info('Activating Workspace Watcher for Git/Husky hooks...');

    // Best-effort live watch: VS Code ignores most of .git/ via files.watcherExclude.
    // .husky/ is reliably observed; static scan covers pre-existing and .git/ paths.
    const huskyWatcher = vscode.workspace.createFileSystemWatcher('**/.husky/*');
    const githooksWatcher = vscode.workspace.createFileSystemWatcher('**/.githooks/*');

    this.watchers.push(huskyWatcher, githooksWatcher);

    for (const watcher of this.watchers) {
      context.subscriptions.push(
        watcher.onDidChange((uri) => this.handleFileChange(uri.fsPath, false)),
        watcher.onDidCreate((uri) => this.handleFileChange(uri.fsPath, false)),
      );
    }

    context.subscriptions.push(
      vscode.workspace.onDidChangeWorkspaceFolders(() => {
        void this.scanAllWorkspaceHooks(true);
      }),
    );

    Logger.info('Workspace Watcher initialized successfully');

    void this.scanAllWorkspaceHooks(true);
  }

  private static async scanAllWorkspaceHooks(isStaticScan: boolean): Promise<void> {
    if (!this.isGitHookAdvisoryEnabled()) {
      return;
    }

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
      return;
    }

    for (const folder of workspaceFolders) {
      const matches = scanWorkspaceRoot(folder.uri.fsPath);
      for (const match of matches) {
        const prefix = isStaticScan ? '[ON-ACTIVATION SCAN] ' : '';
        Logger.warn(
          `${prefix}Workspace Watcher DETECTED MALICIOUS CONTENT in ${match.filePath} (Rule: ${match.rule.name})`,
        );
        await this.triggerSecurityEvent(match, isStaticScan);
      }
    }
  }

  private static async handleFileChange(filePath: string, isStaticScan: boolean): Promise<void> {
    if (!this.isGitHookAdvisoryEnabled()) {
      return;
    }

    try {
      if (!fs.existsSync(filePath)) {
        return;
      }

      const content = fs.readFileSync(filePath, 'utf8');
      const match = matchHookFile(filePath, content);
      if (!match) {
        return;
      }

      const prefix = isStaticScan ? '[ON-ACTIVATION SCAN] ' : '';
      Logger.warn(`${prefix}Workspace Watcher DETECTED MALICIOUS CONTENT in ${filePath} (Rule: ${match.rule.name})`);
      await this.triggerSecurityEvent(match, isStaticScan);
    } catch (err) {
      Logger.error(`Error in WorkspaceWatcher handling file change for ${filePath}`, err as Error);
    }
  }

  /** Resolve the workspace folder root that contains `filePath` (supports multi-root). */
  static resolveWorkspacePathForFile(filePath: string): string | undefined {
    for (const folder of vscode.workspace.workspaceFolders ?? []) {
      const root = folder.uri.fsPath;
      if (filePath === root || filePath.startsWith(`${root}${path.sep}`)) {
        return root;
      }
    }
    return undefined;
  }

  private static async triggerSecurityEvent(match: HookScanMatch, isStaticScan: boolean): Promise<void> {
    const { filePath, rule } = match;
    const workspacePath =
      WorkspaceWatcher.resolveWorkspacePathForFile(filePath) ??
      vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ??
      '';
    const workspaceName =
      vscode.workspace.workspaceFolders?.find((f) => f.uri.fsPath === workspacePath)?.name ??
      vscode.workspace.name ??
      'Unknown Workspace';

    const trustedWorkspaceService = TrustedWorkspaceService.getInstance();
    const isTrusted = workspacePath ? trustedWorkspaceService.isTrusted(workspacePath) : false;

    const workspaceInfo = new WorkspaceInfo(workspaceName, workspacePath, isTrusted);

    const eventTypeLabel = isStaticScan ? 'WorkspaceStaticScan' : 'WorkspaceFileWatch';
    const fsEvent = new FsEvent(filePath, 'write', eventTypeLabel, new ExtensionInfo('workspace.terminal', false));

    const scanType = isStaticScan ? 'STATIC SCAN' : 'WORKSPACE DETECT';
    const ioc: IoC = {
      finding: filePath,
      rule: rule.name,
      description: `[${scanType}] ${rule.description}`,
      confidence: rule.confidence || 1.0,
      severity: rule.severity,
    };

    const securityEvent = new SecurityEvent(fsEvent, workspaceInfo, rule.severity, rule.type, [ioc]);

    await IDEStatusService.emitSecurityEvent(securityEvent);

    if (this.extensionMode === vscode.ExtensionMode.Test) {
      Logger.warn(`CRITICAL ALERT: IDE-SHEPHERD detected a malicious Git hook in ${filePath} (Rule: ${rule.name})`);
      return;
    }

    if (isTrusted) {
      Logger.info(`Workspace Watcher: git-hook alert suppressed — workspace is trusted: ${workspacePath}`);
      return;
    }

    if (!GitHookAlertDedup.shouldShowModal(filePath)) {
      Logger.info(`Workspace Watcher: git-hook modal suppressed (dedup): ${filePath}`);
      return;
    }

    await NotificationService.showMaliciousGitHookAlert(securityEvent, isStaticScan);
  }
}

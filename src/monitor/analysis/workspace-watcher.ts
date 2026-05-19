import * as vscode from 'vscode';
import * as fs from 'fs';
import { Logger } from '../../lib/logger';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { SecurityEvent, IoC } from '../../lib/events/sec-events';
import { FsEvent } from '../../lib/events/fs-events';
import { WorkspaceInfo, ExtensionInfo } from '../../lib/events/ext-events';
import { HookScanMatch, matchHookFile, scanWorkspaceRoot } from './hook-scanner';

export class WorkspaceWatcher {
  private static watchers: vscode.FileSystemWatcher[] = [];
  private static extensionMode: vscode.ExtensionMode = vscode.ExtensionMode.Production;

  public static activate(context: vscode.ExtensionContext): void {
    this.extensionMode = context.extensionMode;
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

  private static async triggerSecurityEvent(match: HookScanMatch, isStaticScan: boolean): Promise<void> {
    const { filePath, rule } = match;
    const workspaceName = vscode.workspace.name || 'Unknown Workspace';
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    const workspacePath = workspaceFolder?.uri.fsPath || '';

    const workspaceInfo = new WorkspaceInfo(workspaceName, workspacePath, false);

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

    const timingMsg = isStaticScan ? 'was found in your workspace upon opening' : 'was just dropped in your workspace';
    const message = `CRITICAL ALERT: IDE-SHEPHERD detected a malicious Git hook that ${timingMsg}!\nFile: ${filePath}\nRule: ${rule.name}`;

    if (this.extensionMode === vscode.ExtensionMode.Test) {
      Logger.warn(message);
      return;
    }

    void vscode.window.showErrorMessage(message, { modal: true }).then(undefined, () => undefined);
  }
}

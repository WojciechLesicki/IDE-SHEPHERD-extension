/**
 * Unit tests for git-hook alert session deduplication
 */

import { expect } from 'chai';
import { GitHookAlertDedup } from '../../monitor/analysis/git-hook-alert-dedup';

suite('GitHookAlertDedup Tests', () => {
  teardown(() => {
    GitHookAlertDedup.resetForTests();
  });

  test('should allow first modal for a hook path', () => {
    expect(GitHookAlertDedup.shouldShowModal('/project/.husky/pre-commit')).to.be.true;
  });

  test('should suppress after markModalShown', () => {
    GitHookAlertDedup.markModalShown('/project/.husky/pre-commit');
    expect(GitHookAlertDedup.shouldShowModal('/project/.husky/pre-commit')).to.be.false;
  });

  test('should normalize Windows paths for dedup', () => {
    GitHookAlertDedup.suppress('C:\\project\\.husky\\pre-commit');
    expect(GitHookAlertDedup.shouldShowModal('c:/project/.husky/pre-commit')).to.be.false;
  });

  test('should suppress after explicit suppress call', () => {
    GitHookAlertDedup.suppress('/project/.husky/pre-commit');
    expect(GitHookAlertDedup.shouldShowModal('/project/.husky/pre-commit')).to.be.false;
  });
});

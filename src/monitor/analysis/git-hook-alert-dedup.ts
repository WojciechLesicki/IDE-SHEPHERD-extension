/**
 * Session-scoped deduplication for git-hook advisory modals.
 * Prevents repeat modals for the same hook file (static scan + watcher + runtime).
 */

function normalizeHookPath(filePath: string): string {
  return filePath.replace(/\\/g, '/').toLowerCase();
}

export class GitHookAlertDedup {
  private static modalShownPaths = new Set<string>();
  private static suppressedPaths = new Set<string>();

  /** Whether a git-hook advisory modal should be shown for this file. */
  static shouldShowModal(filePath: string): boolean {
    const key = normalizeHookPath(filePath);
    return !this.modalShownPaths.has(key) && !this.suppressedPaths.has(key);
  }

  /** Record that a modal was displayed (or is about to be) for this hook file. */
  static markModalShown(filePath: string): void {
    this.modalShownPaths.add(normalizeHookPath(filePath));
  }

  /** Suppress future modals for this hook file (dismiss, remove, or user action). */
  static suppress(filePath: string): void {
    const key = normalizeHookPath(filePath);
    this.suppressedPaths.add(key);
    this.modalShownPaths.add(key);
  }

  /** Reset state — for unit tests only. */
  static resetForTests(): void {
    this.modalShownPaths.clear();
    this.suppressedPaths.clear();
  }
}

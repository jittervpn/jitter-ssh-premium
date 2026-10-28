# Engineering rules
- Keep the VPS installer separate from the panel and storefront to avoid accidental production changes.
- Use an isolated sshd service for tunnel accounts; never rewrite administrative SSH configuration.
- Run all externally supplied commands as argument arrays without a shell to prevent injection.
- Store recoverable credentials encrypted, retain tokens only in root-readable files and never log secrets.
- Serialize account and peer mutations across CLI, timer and HTTP processes with a file lock to prevent race conditions.
- Test logic without root using injected command executors; require disposable-VM validation before a production release.

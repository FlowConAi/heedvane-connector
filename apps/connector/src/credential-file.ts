// The long-lived connector credential is the only state the connector persists. Real
// deployments mount it as a file (HEEDVANE_CREDENTIAL_FILE) so a container restart
// resumes instead of re-enrolling; the enrollment token is single-use and a restart
// without the credential means a fresh enrollment in the hub UI.

import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export function readCredentialFile(path: string): string {
  return readFileSync(path, "utf8");
}

/** Write the credential atomically (tmp file plus rename) with owner-only permissions:
 *  a crash mid-write must not leave a truncated credential, and no other user on the
 *  host should read it. The parent directory is created when missing: the documented
 *  paths (systemd's /var/lib, a fresh mount) do not exist on first boot. */
export function persistCredentialFile(path: string, credential: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmpPath = `${path}.tmp`;
  writeFileSync(tmpPath, `${credential}\n`, "utf8");
  chmodSync(tmpPath, 0o600);
  renameSync(tmpPath, path);
}

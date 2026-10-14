import { useEffect, useMemo, useState } from "react";
import axios from "axios";

const api = axios.create({
  baseURL:
    import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1",
  timeout: 900000,
});

type Asset = {
  id: string;
  hostname: string;
  ip_address: string;
  operating_system?: string | null;
  scanning_enabled: boolean;
};

type Credential = {
  id: string;
  name: string;
  username?: string | null;
  protocol: string;
  auth_method?: string | null;
  port?: number | null;
  failed_attempts: number;
  max_failed_attempts: number;
  lockout_until?: string | null;
  last_used_at?: string | null;
  enabled: boolean;
};

type Evidence = {
  id: string;
  category: string;
  source_type: string;
  source_locator?: string | null;
  observed_value: string;
  confidence: string;
  content_sha256: string;
  captured_at?: string;
};

type Comparison = {
  subject: string;
  unauthenticated_value?: string | null;
  unauthenticated_confidence: string;
  authenticated_value?: string | null;
  authenticated_confidence: string;
  confidence_increased: boolean;
  note: string;
};

type AuthenticatedScan = {
  id: string;
  asset_id: string;
  credential_profile_id?: string | null;
  transport: string;
  collection_mode: string;
  status: string;
  explicitly_authorized: boolean;
  started_at?: string | null;
  completed_at?: string | null;
  error_message?: string | null;
  created_at: string;
};

type ScanResult = {
  scan: AuthenticatedScan;
  evidence: Evidence[];
};

function errorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail;

    if (typeof detail === "string") {
      return detail;
    }

    if (Array.isArray(detail)) {
      return detail
        .map((item) => item?.msg ?? JSON.stringify(item))
        .join(", ");
    }

    if (detail && typeof detail === "object") {
      return JSON.stringify(detail);
    }

    return error.message;
  }

  return error instanceof Error ? error.message : String(error);
}

function formatDate(value?: string | null): string {
  if (!value) return "—";

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;

  return parsed.toLocaleString();
}

function confidenceClass(value: string): string {
  return `badge confidence-${value.toLowerCase().replace(/\s+/g, "-")}`;
}

export default function AuthenticatedAssessmentPanel({
  assets,
}: {
  assets: Asset[];
}) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [comparison, setComparison] = useState<Comparison[]>([]);
  const [lastScan, setLastScan] = useState<AuthenticatedScan | null>(null);

  const [selectedAssetId, setSelectedAssetId] = useState("");
  const [selectedCredentialId, setSelectedCredentialId] = useState("");

  const [loadingCredentials, setLoadingCredentials] = useState(false);
  const [runningScan, setRunningScan] = useState(false);
  const [creatingCredential, setCreatingCredential] = useState(false);
  const [rotatingSecret, setRotatingSecret] = useState(false);

  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const scannableAssets = useMemo(
    () => assets.filter((asset) => asset.scanning_enabled),
    [assets],
  );

  const selectedCredential = useMemo(
    () =>
      credentials.find(
        (credential) => credential.id === selectedCredentialId,
      ) ?? null,
    [credentials, selectedCredentialId],
  );

  async function loadCredentials() {
    setLoadingCredentials(true);

    try {
      const response = await api.get<Credential[]>("/authenticated/credentials");
      setCredentials(response.data);

      setSelectedCredentialId((current) => {
        if (
          current &&
          response.data.some(
            (credential) => credential.id === current && credential.enabled,
          )
        ) {
          return current;
        }

        return response.data.find((credential) => credential.enabled)?.id ?? "";
      });
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoadingCredentials(false);
    }
  }

  useEffect(() => {
    void loadCredentials();
  }, []);

  useEffect(() => {
    if (
      selectedAssetId &&
      !scannableAssets.some((asset) => asset.id === selectedAssetId)
    ) {
      setSelectedAssetId("");
    }

    if (!selectedAssetId && scannableAssets.length > 0) {
      setSelectedAssetId(scannableAssets[0].id);
    }
  }, [scannableAssets, selectedAssetId]);

  async function createCredential(form: HTMLFormElement) {
    const data = new FormData(form);

    setError("");
    setMessage("");
    setCreatingCredential(true);

    try {
      await api.post("/authenticated/credentials", {
        name: String(data.get("name") ?? "").trim(),
        username: String(data.get("username") ?? "").trim(),
        protocol: data.get("protocol"),
        auth_method: data.get("auth_method") ?? "password",
        port: data.get("port") ? Number(data.get("port")) : null,
        secret: data.get("secret"),
        max_failed_attempts: Number(data.get("max_failed_attempts") ?? 3),
        description: String(data.get("description") ?? "").trim() || null,
      });

      form.reset();
      setMessage("Encrypted credential profile created.");
      await loadCredentials();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setCreatingCredential(false);
    }
  }

  async function rotateSecret(form: HTMLFormElement) {
    if (!selectedCredentialId) {
      setError("Select a credential profile first.");
      return;
    }

    const data = new FormData(form);
    const secret = String(data.get("new_secret") ?? "");

    if (!secret) {
      setError("Enter the new secret.");
      return;
    }

    setError("");
    setMessage("");
    setRotatingSecret(true);

    try {
      await api.put(
        `/authenticated/credentials/${selectedCredentialId}/secret`,
        {
          secret,
        },
      );

      form.reset();
      setMessage("Credential secret rotated successfully.");
      await loadCredentials();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRotatingSecret(false);
    }
  }

  async function runAuthenticatedScan(form: HTMLFormElement) {
    const data = new FormData(form);

    setError("");
    setMessage("");
    setEvidence([]);
    setComparison([]);
    setLastScan(null);
    setRunningScan(true);

    try {
      const response = await api.post<ScanResult>("/authenticated/scans", {
        asset_id: data.get("asset_id"),
        credential_profile_id: data.get("credential_id"),
        explicitly_authorized: data.get("auth") === "on",
      });

      setLastScan(response.data.scan);
      setEvidence(response.data.evidence);

      const comparisonResponse = await api.get<{ rows: Comparison[] }>(
        `/authenticated/scans/${response.data.scan.id}/comparison`,
      );

      setComparison(comparisonResponse.data.rows);

      setMessage(
        `Authenticated scan ${response.data.scan.status}: ${response.data.evidence.length} evidence records.`,
      );

      await loadCredentials();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setRunningScan(false);
    }
  }

  return (
    <div className="authenticated-panel">
      {error && (
        <div className="alert danger" role="alert">
          {error}
        </div>
      )}

      {message && (
        <div className="alert success" role="status">
          {message}
        </div>
      )}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Create encrypted credential</h2>
            <p className="hint">
              The password is encrypted before database storage and is never
              returned by the API.
            </p>
          </div>

          <span className="badge">
            {loadingCredentials
              ? "Loading credentials…"
              : `${credentials.length} credential profile${
                  credentials.length === 1 ? "" : "s"
                }`}
          </span>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void createCredential(e.currentTarget);
          }}
        >
          <label>
            Name
            <input
              name="name"
              required
              placeholder="Ubuntu SSH credential"
            />
          </label>

          <label>
            Username
            <input name="username" required placeholder="gihan" />
          </label>

          <label>
            Protocol
            <select name="protocol" defaultValue="ssh">
              <option value="ssh">SSH</option>
              <option value="winrm">WinRM</option>
            </select>
          </label>

          <label>
            Authentication method
            <select name="auth_method" defaultValue="password">
              <option value="password">Password</option>
            </select>
          </label>

          <label>
            Port
            <input
              type="number"
              name="port"
              min="1"
              max="65535"
              placeholder="22 or 5985"
            />
          </label>

          <label>
            Password
            <input
              type="password"
              name="secret"
              required
              autoComplete="new-password"
            />
          </label>

          <label>
            Max failed attempts
            <input
              type="number"
              name="max_failed_attempts"
              min="1"
              max="10"
              defaultValue="3"
            />
          </label>

          <label className="wide">
            Description
            <textarea
              name="description"
              placeholder="Authorized VMware lab credential."
            />
          </label>

          <button type="submit" disabled={creatingCredential}>
            {creatingCredential ? "Creating…" : "Create Credential"}
          </button>
        </form>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Credential profiles</h2>
            <p className="hint">
              Lockout counters and last-use timestamps help prevent accidental
              credential abuse.
            </p>
          </div>

          <button
            type="button"
            onClick={() => void loadCredentials()}
            disabled={loadingCredentials}
          >
            Refresh
          </button>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>User</th>
                <th>Protocol</th>
                <th>Port</th>
                <th>Failed</th>
                <th>Lockout Until</th>
                <th>Last Used</th>
                <th>Enabled</th>
              </tr>
            </thead>
            <tbody>
              {credentials.length === 0 ? (
                <tr>
                  <td colSpan={8} className="empty">
                    No encrypted credential profiles yet.
                  </td>
                </tr>
              ) : (
                credentials.map((credential) => (
                  <tr
                    key={credential.id}
                    className={
                      selectedCredentialId === credential.id
                        ? "selected-row"
                        : ""
                    }
                    onClick={() => setSelectedCredentialId(credential.id)}
                  >
                    <td>{credential.name}</td>
                    <td>{credential.username ?? "—"}</td>
                    <td>{credential.protocol}</td>
                    <td>{credential.port ?? "—"}</td>
                    <td>
                      {credential.failed_attempts}/
                      {credential.max_failed_attempts}
                    </td>
                    <td>{formatDate(credential.lockout_until)}</td>
                    <td>{formatDate(credential.last_used_at)}</td>
                    <td>{credential.enabled ? "Yes" : "No"}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <h2>Rotate selected credential secret</h2>

        <p className="hint">
          Selected profile:{" "}
          <strong>{selectedCredential?.name ?? "None selected"}</strong>
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void rotateSecret(e.currentTarget);
          }}
        >
          <label>
            Credential
            <select
              value={selectedCredentialId}
              onChange={(e) => setSelectedCredentialId(e.target.value)}
              required
            >
              <option value="">Select</option>
              {credentials.map((credential) => (
                <option key={credential.id} value={credential.id}>
                  {credential.name} ({credential.protocol})
                </option>
              ))}
            </select>
          </label>

          <label>
            New password
            <input
              type="password"
              name="new_secret"
              required
              autoComplete="new-password"
            />
          </label>

          <button
            type="submit"
            disabled={!selectedCredentialId || rotatingSecret}
          >
            {rotatingSecret ? "Rotating…" : "Rotate Secret"}
          </button>
        </form>
      </section>

      <section className="panel">
        <h2>Run authorized authenticated scan</h2>

        <p className="hint">
          Use only credentials and systems that are authorized inside the
          VulnForge VMware laboratory. The backend still enforces ScanScope and
          explicit authorization.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void runAuthenticatedScan(e.currentTarget);
          }}
        >
          <label>
            Asset
            <select
              name="asset_id"
              required
              value={selectedAssetId}
              onChange={(e) => setSelectedAssetId(e.target.value)}
            >
              <option value="">Select</option>
              {scannableAssets.map((asset) => (
                <option key={asset.id} value={asset.id}>
                  {asset.hostname} — {asset.ip_address}
                  {asset.operating_system
                    ? ` — ${asset.operating_system}`
                    : ""}
                </option>
              ))}
            </select>
          </label>

          <label>
            Credential
            <select
              name="credential_id"
              required
              value={selectedCredentialId}
              onChange={(e) => setSelectedCredentialId(e.target.value)}
            >
              <option value="">Select</option>
              {credentials
                .filter((credential) => credential.enabled)
                .map((credential) => (
                  <option key={credential.id} value={credential.id}>
                    {credential.name} ({credential.protocol})
                  </option>
                ))}
            </select>
          </label>

          <label className="check">
            <input type="checkbox" name="auth" /> Explicitly authorized
          </label>

          <button
            type="submit"
            disabled={
              runningScan ||
              !selectedAssetId ||
              !selectedCredentialId
            }
          >
            {runningScan
              ? "Running Assessment…"
              : "Run Authenticated Assessment"}
          </button>
        </form>
      </section>

      {lastScan && (
        <section
          className={`result ${
            lastScan.status.toLowerCase() === "completed"
              ? "allowed"
              : ""
          }`}
        >
          <div className="panel-heading">
            <h2>Latest authenticated scan</h2>
            <span className="badge">{lastScan.status}</span>
          </div>

          <div className="detail-grid">
            <div>
              <small>Scan ID</small>
              <strong>{lastScan.id}</strong>
            </div>
            <div>
              <small>Transport</small>
              <strong>{lastScan.transport}</strong>
            </div>
            <div>
              <small>Collection Mode</small>
              <strong>{lastScan.collection_mode}</strong>
            </div>
            <div>
              <small>Started</small>
              <strong>{formatDate(lastScan.started_at)}</strong>
            </div>
            <div>
              <small>Completed</small>
              <strong>{formatDate(lastScan.completed_at)}</strong>
            </div>
            <div>
              <small>Evidence</small>
              <strong>{evidence.length}</strong>
            </div>
          </div>

          {lastScan.error_message && (
            <p className="warning-text">{lastScan.error_message}</p>
          )}
        </section>
      )}

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Authenticated evidence</h2>
            <p className="hint">
              Evidence content is displayed for review; hashes remain available
              for integrity verification.
            </p>
          </div>

          <span className="badge">{evidence.length} records</span>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Category</th>
                <th>Source</th>
                <th>Confidence</th>
                <th>Evidence</th>
                <th>SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {evidence.length === 0 ? (
                <tr>
                  <td colSpan={5} className="empty">
                    Run an authenticated assessment to load evidence.
                  </td>
                </tr>
              ) : (
                evidence.map((item) => (
                  <tr key={item.id}>
                    <td>{item.category}</td>
                    <td>
                      <div>{item.source_type}</div>
                      {item.source_locator && (
                        <small className="muted">
                          {item.source_locator}
                        </small>
                      )}
                    </td>
                    <td>
                      <span className={confidenceClass(item.confidence)}>
                        {item.confidence}
                      </span>
                    </td>
                    <td className="wrap-cell">
                      {item.observed_value.slice(0, 1000)}
                    </td>
                    <td className="hash-cell">{item.content_sha256}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Unauthenticated vs authenticated</h2>
            <p className="hint">
              This view shows where authenticated evidence increases certainty
              instead of treating network observations as confirmed local state.
            </p>
          </div>

          <span className="badge">{comparison.length} comparisons</span>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Subject</th>
                <th>Unauth Value</th>
                <th>Unauth Confidence</th>
                <th>Auth Value</th>
                <th>Auth Confidence</th>
                <th>Increased?</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {comparison.length === 0 ? (
                <tr>
                  <td colSpan={7} className="empty">
                    No comparison loaded yet.
                  </td>
                </tr>
              ) : (
                comparison.map((item, index) => (
                  <tr key={`${item.subject}-${index}`}>
                    <td>{item.subject}</td>
                    <td className="wrap-cell">
                      {item.unauthenticated_value ?? "—"}
                    </td>
                    <td>
                      <span
                        className={confidenceClass(
                          item.unauthenticated_confidence,
                        )}
                      >
                        {item.unauthenticated_confidence}
                      </span>
                    </td>
                    <td className="wrap-cell">
                      {item.authenticated_value ?? "—"}
                    </td>
                    <td>
                      <span
                        className={confidenceClass(
                          item.authenticated_confidence,
                        )}
                      >
                        {item.authenticated_confidence}
                      </span>
                    </td>
                    <td>{item.confidence_increased ? "Yes" : "No"}</td>
                    <td className="wrap-cell">{item.note}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

import { useEffect, useState } from "react";
import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1",
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
  port?: number | null;
  failed_attempts: number;
  max_failed_attempts: number;
  lockout_until?: string | null;
  enabled: boolean;
};
type Evidence = {
  id: string;
  category: string;
  source_type: string;
  observed_value: string;
  confidence: string;
  content_sha256: string;
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

export default function AuthenticatedAssessmentPanel({
  assets,
}: {
  assets: Asset[];
}) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [comparison, setComparison] = useState<Comparison[]>([]);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  async function load() {
    try {
      const r = await api.get("/authenticated/credentials");
      setCredentials(r.data);
    } catch (e) {
      setError(
        axios.isAxiosError(e)
          ? String(e.response?.data?.detail ?? e.message)
          : String(e),
      );
    }
  }
  useEffect(() => {
    load();
  }, []);
  return (
    <div>
      {error && <div className="alert danger">{error}</div>}
      {message && <div className="alert success">{message}</div>}
      <section className="panel">
        <h2>Create encrypted credential</h2>
        <p className="hint">
          The password is encrypted before database storage and is never
          returned by the API.
        </p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            const f = e.currentTarget,
              d = new FormData(f);
            try {
              await api.post("/authenticated/credentials", {
                name: d.get("name"),
                username: d.get("username"),
                protocol: d.get("protocol"),
                auth_method: "password",
                port: d.get("port") ? Number(d.get("port")) : null,
                secret: d.get("secret"),
                max_failed_attempts: Number(d.get("max_failed_attempts")),
                description: d.get("description"),
              });
              f.reset();
              setMessage("Encrypted credential profile created.");
              await load();
            } catch (x) {
              setError(
                axios.isAxiosError(x)
                  ? String(x.response?.data?.detail ?? x.message)
                  : String(x),
              );
            }
          }}
        >
          <label>
            Name
            <input name="name" required />
          </label>
          <label>
            Username
            <input name="username" required />
          </label>
          <label>
            Protocol
            <select name="protocol">
              <option value="ssh">SSH</option>
              <option value="winrm">WinRM</option>
            </select>
          </label>
          <label>
            Port
            <input type="number" name="port" placeholder="22 or 5985" />
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
            <textarea name="description" />
          </label>
          <button>Create Credential</button>
        </form>
      </section>
      <section className="panel">
        <h2>Run authorized authenticated scan</h2>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            const d = new FormData(e.currentTarget);
            setEvidence([]);
            setComparison([]);
            try {
              const r = await api.post("/authenticated/scans", {
                asset_id: d.get("asset_id"),
                credential_profile_id: d.get("credential_id"),
                explicitly_authorized: d.get("auth") === "on",
              });
              setEvidence(r.data.evidence);
              const c = await api.get(
                `/authenticated/scans/${r.data.scan.id}/comparison`,
              );
              setComparison(c.data.rows);
              setMessage(
                `Authenticated scan ${r.data.scan.status}: ${r.data.evidence.length} evidence records.`,
              );
            } catch (x) {
              setError(
                axios.isAxiosError(x)
                  ? String(x.response?.data?.detail ?? x.message)
                  : String(x),
              );
            }
          }}
        >
          <label>
            Asset
            <select name="asset_id" required>
              <option value="">Select</option>
              {assets
                .filter((a) => a.scanning_enabled)
                .map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.hostname} — {a.ip_address}
                  </option>
                ))}
            </select>
          </label>
          <label>
            Credential
            <select name="credential_id" required>
              <option value="">Select</option>
              {credentials
                .filter((c) => c.enabled)
                .map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.protocol})
                  </option>
                ))}
            </select>
          </label>
          <label className="check">
            <input type="checkbox" name="auth" /> Explicitly authorized
          </label>
          <button>Run Authenticated Assessment</button>
        </form>
      </section>
      <section className="panel">
        <h2>Authenticated evidence</h2>
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
              {evidence.map((x) => (
                <tr key={x.id}>
                  <td>{x.category}</td>
                  <td>{x.source_type}</td>
                  <td>{x.confidence}</td>
                  <td className="wrap-cell">
                    {x.observed_value.slice(0, 500)}
                  </td>
                  <td>{x.content_sha256}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <h2>Unauthenticated vs authenticated</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Subject</th>
                <th>Unauth confidence</th>
                <th>Auth confidence</th>
                <th>Increased?</th>
                <th>Note</th>
              </tr>
            </thead>
            <tbody>
              {comparison.map((x, i) => (
                <tr key={i}>
                  <td>{x.subject}</td>
                  <td>{x.unauthenticated_confidence}</td>
                  <td>{x.authenticated_confidence}</td>
                  <td>{x.confidence_increased ? "Yes" : "No"}</td>
                  <td className="wrap-cell">{x.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

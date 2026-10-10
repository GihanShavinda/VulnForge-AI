import { FormEvent, useEffect, useState } from "react";
import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1",
  timeout: 15000,
});

type Network = {
  id: string;
  name: string;
  cidr: string;
  network_type: string;
  approved_for_scanning: boolean;
};
type Asset = {
  id: string;
  network_id: string;
  hostname: string;
  ip_address: string;
  mac_address?: string | null;
  vendor?: string | null;
  operating_system?: string | null;
  role?: string | null;
  scanning_enabled: boolean;
  reachable?: boolean | null;
  first_seen?: string | null;
  last_seen?: string | null;
  last_discovery_source?: string | null;
};
type Scope = {
  id: string;
  name: string;
  network_id: string;
  cidr: string;
  enabled: boolean;
  require_explicit_authorization: boolean;
  maintenance_start?: string | null;
  maintenance_end?: string | null;
};
type Profile = {
  id: string;
  name: string;
  scanner_type: string;
  timeout_seconds: number;
  max_concurrency: number;
  evidence_retention_days: number;
  enabled: boolean;
};
type Tag = { id: string; name: string; description?: string | null };
type Credential = {
  id: string;
  name: string;
  username?: string | null;
  secret_reference: string;
  protocol: string;
  enabled: boolean;
};
type Audit = {
  id: string;
  event_type: string;
  target?: string | null;
  allowed?: boolean | null;
  reason?: string | null;
  created_at: string;
};
type Validation = {
  target: string;
  normalized_target?: string | null;
  allowed: boolean;
  matched_scope?: string | null;
  reason: string;
};
type DiscoveryHost = {
  id: string;
  discovery_job_id: string;
  matched_asset_id?: string | null;
  ip_address: string;
  hostname?: string | null;
  mac_address?: string | null;
  vendor?: string | null;
  reachable: boolean;
  state: string;
  first_seen: string;
  last_seen: string;
  scan_source: string;
  scan_timestamp: string;
  identity_basis?: string | null;
  change_types?: string | null;
};
type DiscoveryJob = {
  id: string;
  target: string;
  discovery_method: string;
  scan_source: string;
  status: string;
  created_at: string;
};
type DiscoveryResult = { job: DiscoveryJob; hosts: DiscoveryHost[] };
type DiscoveryEvidence = {
  id: string;
  discovery_job_id: string;
  content_sha256: string;
  raw_xml: string;
  captured_at: string;
};

type Tab =
  | "dashboard"
  | "networks"
  | "assets"
  | "scopes"
  | "profiles"
  | "tags"
  | "credentials"
  | "validator"
  | "discovery"
  | "audit";

function errMessage(e: unknown) {
  if (axios.isAxiosError(e)) {
    const d = e.response?.data?.detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d))
      return d.map((x) => x.msg ?? JSON.stringify(x)).join(", ");
    return e.message;
  }
  return e instanceof Error ? e.message : "Unexpected error";
}

function Table({
  headers,
  rows,
}: {
  headers: string[];
  rows: (string | number | boolean)[][];
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {headers.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={headers.length} className="empty">
                No records yet.
              </td>
            </tr>
          ) : (
            rows.map((r, i) => (
              <tr key={i}>
                {r.map((c, j) => (
                  <td key={j}>{String(c)}</td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [networks, setNetworks] = useState<Network[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [tags, setTags] = useState<Tag[]>([]);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [validation, setValidation] = useState<Validation | null>(null);
  const [discovered, setDiscovered] = useState<DiscoveryHost[]>([]);
  const [lastDiscovery, setLastDiscovery] = useState<DiscoveryResult | null>(
    null,
  );
  const [evidence, setEvidence] = useState<DiscoveryEvidence | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function refresh() {
    try {
      const [n, a, s, p, t, c, l, d] = await Promise.all([
        api.get("/security-lab/networks"),
        api.get("/security-lab/assets"),
        api.get("/security-lab/scopes"),
        api.get("/security-lab/scan-profiles"),
        api.get("/security-lab/asset-tags"),
        api.get("/security-lab/credential-profiles"),
        api.get("/security-lab/audit-logs?limit=100"),
        api.get("/assets/discovered"),
      ]);
      setNetworks(n.data);
      setAssets(a.data);
      setScopes(s.data);
      setProfiles(p.data);
      setTags(t.data);
      setCredentials(c.data);
      setAudit(l.data);
      setDiscovered(d.data);
      setError("");
    } catch (e) {
      setError("Backend unavailable or API mismatch: " + errMessage(e));
    }
  }
  useEffect(() => {
    refresh();
  }, []);

  async function submit(
    path: string,
    payload: unknown,
    form: HTMLFormElement,
    ok: string,
  ) {
    setError("");
    setMessage("");
    try {
      await api.post(path, payload);
      form.reset();
      setMessage(ok);
      await refresh();
    } catch (e) {
      setError(errMessage(e));
    }
  }

  const nav: (Tab | string)[] = [
    "dashboard",
    "networks",
    "assets",
    "scopes",
    "profiles",
    "tags",
    "credentials",
    "validator",
    "discovery",
    "audit",
  ];

  return (
    <div className="shell">
      <aside>
        <div className="brand">
          <b>VF</b>
          <div>
            <strong>VulnForge AI</strong>
            <small>V2 Asset Discovery</small>
          </div>
        </div>
        <nav>
          {nav.map((x) => (
            <button
              key={x}
              className={tab === x ? "active" : ""}
              onClick={() => setTab(x as Tab)}
            >
              {x.replace("-", " ").replace(/^./, (m) => m.toUpperCase())}
            </button>
          ))}
        </nav>
        <div className="warning">
          Authorized lab only.
          <br />
          No automatic exploitation.
        </div>
      </aside>
      <main>
        <header>
          <div>
            <h1>
              {tab === "dashboard"
                ? "Security Lab Dashboard"
                : tab.replace(/^./, (m) => m.toUpperCase())}
            </h1>
            <p>V2 safe network asset discovery with Nmap XML evidence.</p>
          </div>
          <span>V2</span>
        </header>
        {error && <div className="alert danger">{error}</div>}
        {message && <div className="alert success">{message}</div>}

        {tab === "dashboard" && (
          <>
            <section className="stats">
              <article>
                <small>Networks</small>
                <b>{networks.length}</b>
              </article>
              <article>
                <small>Assets</small>
                <b>{assets.length}</b>
              </article>
              <article>
                <small>Enabled Scopes</small>
                <b>{scopes.filter((x) => x.enabled).length}</b>
              </article>
              <article>
                <small>Profiles</small>
                <b>{profiles.length}</b>
              </article>
              <article>
                <small>Denied Validations</small>
                <b>{audit.filter((x) => x.allowed === false).length}</b>
              </article>
              <article>
                <small>Discovery Observations</small>
                <b>{discovered.length}</b>
              </article>
            </section>
            <section className="panel">
              <h2>V2 discovery flow</h2>
              <div className="flow">
                <span>Approved Network</span>→<span>Scan Scope</span>→
                <span>Nmap Discovery</span>→<span>XML Evidence</span>→
                <span>Reconciliation</span>→<span>Change Detection</span>
              </div>
            </section>
          </>
        )}

        {tab === "networks" && (
          <>
            <section className="panel">
              <h2>Create network</h2>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const f = e.currentTarget,
                    d = new FormData(f);
                  submit(
                    "/security-lab/networks",
                    {
                      name: d.get("name"),
                      cidr: d.get("cidr"),
                      network_type: d.get("network_type"),
                      approved_for_scanning: d.get("approved") === "on",
                      description: d.get("description"),
                    },
                    f,
                    "Network created.",
                  );
                }}
              >
                <label>
                  Name
                  <input
                    name="name"
                    required
                    placeholder="VulnForge VMware Lab"
                  />
                </label>
                <label>
                  CIDR
                  <input name="cidr" required defaultValue="192.168.56.0/24" />
                </label>
                <label>
                  Type
                  <select name="network_type" defaultValue="host-only">
                    <option>host-only</option>
                    <option>nat</option>
                  </select>
                </label>
                <label className="check">
                  <input type="checkbox" name="approved" /> Approved for
                  scanning
                </label>
                <label className="wide">
                  Description
                  <textarea name="description" />
                </label>
                <button>Create Network</button>
              </form>
            </section>
            <section className="panel">
              <Table
                headers={["Name", "CIDR", "Type", "Approved"]}
                rows={networks.map((x) => [
                  x.name,
                  x.cidr,
                  x.network_type,
                  x.approved_for_scanning ? "Yes" : "No",
                ])}
              />
            </section>
          </>
        )}

        {tab === "assets" && (
          <>
            <section className="panel">
              <h2>Add asset</h2>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const f = e.currentTarget,
                    d = new FormData(f);
                  submit(
                    "/security-lab/assets",
                    {
                      network_id: d.get("network_id"),
                      hostname: d.get("hostname"),
                      ip_address: d.get("ip_address"),
                      operating_system: d.get("os"),
                      role: d.get("role"),
                      is_vulnerable_target: d.get("vulnerable") === "on",
                      scanning_enabled: d.get("enabled") === "on",
                      notes: d.get("notes"),
                    },
                    f,
                    "Asset created.",
                  );
                }}
              >
                <label>
                  Network
                  <select name="network_id" required>
                    <option value="">Select</option>
                    {networks.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name} ({n.cidr})
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Hostname
                  <input name="hostname" required />
                </label>
                <label>
                  IP address
                  <input
                    name="ip_address"
                    required
                    placeholder="192.168.56.20"
                  />
                </label>
                <label>
                  OS
                  <input name="os" />
                </label>
                <label>
                  Role
                  <input name="role" />
                </label>
                <label className="check">
                  <input type="checkbox" name="vulnerable" /> Vulnerable target
                </label>
                <label className="check">
                  <input type="checkbox" name="enabled" defaultChecked />{" "}
                  Scanning enabled
                </label>
                <label className="wide">
                  Notes
                  <textarea name="notes" />
                </label>
                <button>Add Asset</button>
              </form>
            </section>
            <section className="panel">
              <Table
                headers={["Hostname", "IP", "OS", "Role", "Scanning"]}
                rows={assets.map((x) => [
                  x.hostname,
                  x.ip_address,
                  x.operating_system ?? "—",
                  x.role ?? "—",
                  x.scanning_enabled ? "Yes" : "No",
                ])}
              />
            </section>
          </>
        )}

        {tab === "scopes" && (
          <>
            <section className="panel">
              <h2>Create scan scope</h2>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const f = e.currentTarget,
                    d = new FormData(f);
                  const ms = d.get("start")
                    ? String(d.get("start")) + ":00"
                    : null;
                  const me = d.get("end") ? String(d.get("end")) + ":00" : null;
                  submit(
                    "/security-lab/scopes",
                    {
                      name: d.get("name"),
                      network_id: d.get("network_id"),
                      cidr: d.get("cidr"),
                      enabled: d.get("enabled") === "on",
                      require_explicit_authorization: d.get("auth") === "on",
                      maintenance_start: ms,
                      maintenance_end: me,
                      timezone_name: d.get("tz"),
                    },
                    f,
                    "Scope created.",
                  );
                }}
              >
                <label>
                  Name
                  <input name="name" required placeholder="Primary Lab Scope" />
                </label>
                <label>
                  Network
                  <select name="network_id" required>
                    <option value="">Select</option>
                    {networks.map((n) => (
                      <option key={n.id} value={n.id}>
                        {n.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  CIDR
                  <input name="cidr" defaultValue="192.168.56.0/24" required />
                </label>
                <label>
                  Timezone
                  <input name="tz" defaultValue="Asia/Colombo" required />
                </label>
                <label>
                  Start
                  <input type="time" name="start" />
                </label>
                <label>
                  End
                  <input type="time" name="end" />
                </label>
                <label className="check">
                  <input type="checkbox" name="enabled" defaultChecked />{" "}
                  Enabled
                </label>
                <label className="check">
                  <input type="checkbox" name="auth" defaultChecked /> Require
                  explicit authorization
                </label>
                <button>Create Scope</button>
              </form>
            </section>
            <section className="panel">
              <Table
                headers={["Name", "CIDR", "Enabled", "Authorization", "Window"]}
                rows={scopes.map((x) => [
                  x.name,
                  x.cidr,
                  x.enabled ? "Yes" : "No",
                  x.require_explicit_authorization ? "Required" : "No",
                  x.maintenance_start && x.maintenance_end
                    ? `${x.maintenance_start}-${x.maintenance_end}`
                    : "Always",
                ])}
              />
            </section>
          </>
        )}

        {tab === "profiles" && (
          <>
            <section className="panel">
              <h2>Create scan profile</h2>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const f = e.currentTarget,
                    d = new FormData(f);
                  submit(
                    "/security-lab/scan-profiles",
                    {
                      name: d.get("name"),
                      scanner_type: d.get("scanner"),
                      timeout_seconds: Number(d.get("timeout")),
                      max_concurrency: Number(d.get("concurrency")),
                      evidence_retention_days: Number(d.get("retention")),
                      require_scope_validation: true,
                      require_authorization: true,
                      enabled: d.get("enabled") === "on",
                      description: d.get("description"),
                    },
                    f,
                    "Scan profile created.",
                  );
                }}
              >
                <label>
                  Name
                  <input
                    name="name"
                    required
                    defaultValue="Safe Nmap Baseline"
                  />
                </label>
                <label>
                  Scanner
                  <select name="scanner">
                    <option>nmap</option>
                    <option>nuclei</option>
                    <option>openvas</option>
                  </select>
                </label>
                <label>
                  Timeout seconds
                  <input type="number" name="timeout" defaultValue="900" />
                </label>
                <label>
                  Concurrency
                  <input type="number" name="concurrency" defaultValue="2" />
                </label>
                <label>
                  Retention days
                  <input type="number" name="retention" defaultValue="90" />
                </label>
                <label className="check">
                  <input type="checkbox" name="enabled" defaultChecked />{" "}
                  Enabled
                </label>
                <label className="wide">
                  Description
                  <textarea name="description" />
                </label>
                <button>Create Profile</button>
              </form>
            </section>
            <section className="panel">
              <Table
                headers={[
                  "Name",
                  "Scanner",
                  "Timeout",
                  "Concurrency",
                  "Retention",
                  "Enabled",
                ]}
                rows={profiles.map((x) => [
                  x.name,
                  x.scanner_type,
                  x.timeout_seconds,
                  x.max_concurrency,
                  x.evidence_retention_days,
                  x.enabled ? "Yes" : "No",
                ])}
              />
            </section>
          </>
        )}

        {tab === "tags" && (
          <>
            <section className="panel">
              <h2>Create asset tag</h2>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const f = e.currentTarget,
                    d = new FormData(f);
                  submit(
                    "/security-lab/asset-tags",
                    { name: d.get("name"), description: d.get("description") },
                    f,
                    "Asset tag created.",
                  );
                }}
              >
                <label>
                  Name
                  <input name="name" required placeholder="legacy-os" />
                </label>
                <label className="wide">
                  Description
                  <textarea name="description" />
                </label>
                <button>Create Tag</button>
              </form>
            </section>
            <section className="panel">
              <Table
                headers={["Name", "Description"]}
                rows={tags.map((x) => [x.name, x.description ?? "—"])}
              />
            </section>
          </>
        )}

        {tab === "credentials" && (
          <>
            <section className="panel">
              <h2>Create credential profile</h2>
              <p className="hint">
                Store a secret reference only, never the plaintext password.
              </p>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const f = e.currentTarget,
                    d = new FormData(f);
                  submit(
                    "/security-lab/credential-profiles",
                    {
                      name: d.get("name"),
                      username: d.get("username"),
                      secret_reference: d.get("secret_reference"),
                      protocol: d.get("protocol"),
                      description: d.get("description"),
                      enabled: d.get("enabled") === "on",
                    },
                    f,
                    "Credential profile created.",
                  );
                }}
              >
                <label>
                  Name
                  <input name="name" required />
                </label>
                <label>
                  Protocol
                  <select name="protocol">
                    <option>ssh</option>
                    <option>winrm</option>
                    <option>smb</option>
                    <option>http</option>
                  </select>
                </label>
                <label>
                  Username
                  <input name="username" />
                </label>
                <label>
                  Secret reference
                  <input
                    name="secret_reference"
                    required
                    placeholder="windows-credential-manager:vulnforge/lab-ssh"
                  />
                </label>
                <label className="check">
                  <input type="checkbox" name="enabled" defaultChecked />{" "}
                  Enabled
                </label>
                <label className="wide">
                  Description
                  <textarea name="description" />
                </label>
                <button>Create Credential Profile</button>
              </form>
            </section>
            <section className="panel">
              <Table
                headers={[
                  "Name",
                  "Protocol",
                  "Username",
                  "Secret Reference",
                  "Enabled",
                ]}
                rows={credentials.map((x) => [
                  x.name,
                  x.protocol,
                  x.username ?? "—",
                  x.secret_reference,
                  x.enabled ? "Yes" : "No",
                ])}
              />
            </section>
          </>
        )}

        {tab === "validator" && (
          <>
            <section className="panel">
              <h2>Validate target</h2>
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  const f = e.currentTarget,
                    d = new FormData(f);
                  setError("");
                  try {
                    const r = await api.post("/security-lab/validate-target", {
                      target: d.get("target"),
                      explicitly_authorized: d.get("auth") === "on",
                    });
                    setValidation(r.data);
                    await refresh();
                  } catch (x) {
                    setError(errMessage(x));
                  }
                }}
              >
                <label>
                  Literal IP
                  <input name="target" required placeholder="192.168.56.20" />
                </label>
                <label className="check">
                  <input type="checkbox" name="auth" /> Explicitly authorized
                </label>
                <button>Validate</button>
              </form>
            </section>
            {validation && (
              <section
                className={`result ${validation.allowed ? "allowed" : "denied"}`}
              >
                <h2>{validation.allowed ? "ALLOWED" : "DENIED"}</h2>
                <p>
                  <b>Target:</b> {validation.target}
                </p>
                <p>
                  <b>Matched scope:</b> {validation.matched_scope ?? "—"}
                </p>
                <p>
                  <b>Reason:</b> {validation.reason}
                </p>
              </section>
            )}
          </>
        )}

        {tab === "discovery" && (
          <>
            <section className="panel">
              <h2>Run Nmap discovery</h2>
              <p className="hint">
                The backend validates the entire IP/CIDR against an approved
                ScanScope before Nmap starts. Use only your authorized VMware
                lab range.
              </p>
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  const f = e.currentTarget,
                    d = new FormData(f);
                  setError("");
                  setMessage("");
                  setEvidence(null);
                  try {
                    const r = await api.post(
                      "/scans/discovery",
                      {
                        target: d.get("target"),
                        discovery_method: d.get("method"),
                        explicitly_authorized: d.get("auth") === "on",
                      },
                      { timeout: 360000 },
                    );
                    setLastDiscovery(r.data);
                    setMessage(
                      `Discovery completed: ${r.data.hosts.length} observations.`,
                    );
                    await refresh();
                  } catch (x) {
                    setError(errMessage(x));
                  }
                }}
              >
                <label>
                  Target IP/CIDR
                  <input
                    name="target"
                    required
                    defaultValue="192.168.56.0/24"
                  />
                </label>
                <label>
                  Discovery method
                  <select name="method" defaultValue="arp">
                    <option value="icmp">ICMP</option>
                    <option value="arp">
                      ARP (best for local Host-Only LAN)
                    </option>
                    <option value="tcp">TCP probes</option>
                  </select>
                </label>
                <label className="check">
                  <input type="checkbox" name="auth" /> Explicitly authorized
                </label>
                <button>Run Discovery</button>
              </form>
            </section>
            {lastDiscovery && (
              <section className="panel">
                <h2>Latest job</h2>
                <p>
                  <b>ID:</b> {lastDiscovery.job.id}
                </p>
                <p>
                  <b>Target:</b> {lastDiscovery.job.target}
                </p>
                <p>
                  <b>Method:</b> {lastDiscovery.job.discovery_method}
                </p>
                <p>
                  <b>Status:</b> {lastDiscovery.job.status}
                </p>
                <button
                  onClick={async () => {
                    try {
                      const r = await api.get(
                        `/scans/${lastDiscovery.job.id}/evidence`,
                      );
                      setEvidence(r.data);
                    } catch (x) {
                      setError(errMessage(x));
                    }
                  }}
                >
                  Load Raw XML Evidence
                </button>
              </section>
            )}
            {evidence && (
              <section className="panel">
                <h2>Raw Nmap XML evidence</h2>
                <p className="hint">SHA-256: {evidence.content_sha256}</p>
                <pre className="evidence">{evidence.raw_xml}</pre>
              </section>
            )}
            <section className="panel">
              <h2>Discovered hosts and change signals</h2>
              <button onClick={refresh}>Refresh</button>
              <Table
                headers={[
                  "Scan Time",
                  "IP",
                  "Hostname",
                  "MAC",
                  "Vendor",
                  "State",
                  "Identity",
                  "Changes",
                ]}
                rows={discovered.map((x) => [
                  new Date(x.scan_timestamp).toLocaleString(),
                  x.ip_address,
                  x.hostname ?? "—",
                  x.mac_address ?? "—",
                  x.vendor ?? "—",
                  x.state,
                  x.identity_basis ?? "—",
                  x.change_types ?? "—",
                ])}
              />
            </section>
          </>
        )}

        {tab === "audit" && (
          <section className="panel">
            <button onClick={refresh}>Refresh</button>
            <Table
              headers={["Time", "Event", "Target", "Decision", "Reason"]}
              rows={audit.map((x) => [
                new Date(x.created_at).toLocaleString(),
                x.event_type,
                x.target ?? "—",
                x.allowed == null ? "—" : x.allowed ? "Allowed" : "Denied",
                x.reason ?? "—",
              ])}
            />
          </section>
        )}
      </main>
    </div>
  );
}

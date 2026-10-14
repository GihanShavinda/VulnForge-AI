import { useEffect, useState } from "react";

import LegacyV1V5Workspace from "./LegacyV1V5Workspace";
import PostV5Workspace from "./PostV5Workspace";

type Workspace = "lab" | "platform";

const WORKSPACE_STORAGE_KEY = "vulnforge-workspace";

export default function App() {
  const [workspace, setWorkspace] = useState<Workspace>(() => {
    const saved = window.localStorage.getItem(WORKSPACE_STORAGE_KEY);
    return saved === "lab" ? "lab" : "platform";
  });

  useEffect(() => {
    window.localStorage.setItem(WORKSPACE_STORAGE_KEY, workspace);
  }, [workspace]);

  return (
    <>
      <div
        className="workspace-switcher"
        role="navigation"
        aria-label="VulnForge workspace"
      >
        <button
          type="button"
          className={workspace === "lab" ? "active" : ""}
          aria-pressed={workspace === "lab"}
          onClick={() => setWorkspace("lab")}
        >
          V1–V5 Lab
        </button>

        <button
          type="button"
          className={workspace === "platform" ? "active" : ""}
          aria-pressed={workspace === "platform"}
          onClick={() => setWorkspace("platform")}
        >
          V6–V20 Platform
        </button>
      </div>

      {workspace === "lab" ? <LegacyV1V5Workspace /> : <PostV5Workspace />}
    </>
  );
}

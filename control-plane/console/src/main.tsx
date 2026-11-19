import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import { AuthProvider, makeUserManager } from "./auth";
import { loadConfig } from "./config";
import "./styles.css";

const root = createRoot(document.getElementById("root")!);

loadConfig()
  .then((config) => {
    root.render(
      <StrictMode>
        <AuthProvider manager={makeUserManager(config)}>
          <App config={config} />
        </AuthProvider>
      </StrictMode>,
    );
  })
  .catch((e: unknown) => {
    root.render(
      <main className="centered">
        <h1>OPLIA Console</h1>
        <div className="note note-danger" role="alert">
          The console configuration could not be loaded: {e instanceof Error ? e.message : String(e)}
        </div>
      </main>,
    );
  });

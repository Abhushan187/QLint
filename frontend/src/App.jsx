import { useEffect, useState } from "react";

export default function App() {
  const [status, setStatus] = useState("Checking backend...");

  useEffect(() => {
    const controller = new AbortController();

    fetch("http://localhost:8000/health", { signal: controller.signal })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => {
        setStatus(data.status === "ok" ? "Backend connected" : "Backend unreachable");
      })
      .catch((err) => {
        if (err.name !== "AbortError") setStatus("Backend unreachable");
      });

    return () => controller.abort();
  }, []);

  return (
    <div className="app">
      <h1>PQC Migration Scanner</h1>
      <p className="status">{status}</p>
    </div>
  );
}

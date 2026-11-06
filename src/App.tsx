import { useMemo } from "react";
import { buildPortfolio, formatRisk, slaStatus } from "./findings.js";
import { findings } from "./seed.js";

const TODAY = "2026-11-06";

export function App() {
  const portfolio = useMemo(() => buildPortfolio(findings, TODAY), []);

  return (
    <div className="shell">
      <header className="masthead">
        <div>
          <p className="eyebrow">Bastion · findings triage</p>
          <h1>Find the signal. Fix the risk.</h1>
          <p className="lede">CVSS base scoring, asset-weighted risk, duplicate suppression and remediation SLAs in one security portfolio.</p>
        </div>
        <div className="mast-meta"><span>CVSS 3.1</span><span>14 findings</span><span>Risk-based</span></div>
      </header>

      <section className="metrics">
        <Metric label="Unique findings" value={String(portfolio.unique)} />
        <Metric label="Critical" value={String(portfolio.critical)} tone="alert" />
        <Metric label="Average risk" value={formatRisk(portfolio.averageRisk)} tone="blue" />
        <Metric label="Overdue" value={String(portfolio.overdue)} tone="alert" />
        <Metric label="Duplicates removed" value={String(portfolio.duplicates)} tone="green" />
      </section>

      <main className="grid">
        <section className="panel">
          <div className="panel-head"><h2>Finding queue</h2><span>{portfolio.unique} unique · {portfolio.total} raw</span></div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Finding</th><th>Asset</th><th className="num">CVSS</th><th className="num">Risk</th><th>Severity</th><th>SLA</th></tr></thead>
              <tbody>
                {portfolio.findings.map((item) => {
                  const status = slaStatus(item, TODAY);
                  return (
                    <tr key={item.id}>
                      <td><strong>{item.title}</strong><small>{item.id} · {item.vector}</small></td>
                      <td>{item.asset}<small>{item.exposure}</small></td>
                      <td className="num">{item.cvss.baseScore.toFixed(1)}</td>
                      <td className="num">{formatRisk(item.riskScore)}</td>
                      <td><span className={`sev ${item.cvss.severity}`}>{item.cvss.severity}</span></td>
                      <td><span className={`sla ${status}`}>{status}</span><small>due {item.dueDate}</small></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="panel side">
          <div className="panel-head"><h2>Severity mix</h2></div>
          <div className="mix">
            <div><span>Critical</span><strong>{portfolio.critical}</strong></div>
            <div><span>High</span><strong>{portfolio.high}</strong></div>
            <div><span>Medium</span><strong>{portfolio.medium}</strong></div>
            <div><span>Low</span><strong>{portfolio.low}</strong></div>
          </div>
          <div className="callout">
            <strong>Risk formula</strong>
            <p>CVSS base × asset criticality × exposure × 10, capped at 100. Critical findings carry a 7-day remediation SLA.</p>
          </div>
        </aside>

        <section className="panel notes">
          <div className="panel-head"><h2>How triage works</h2></div>
          <div className="note-grid">
            <Note title="Score" body="CVSS 3.1 base metrics combine impact and exploitability; scope changes use the 1.08 multiplier." />
            <Note title="Weight" body="Asset criticality (1–5) and internet/partner/internal exposure turn a vector into a risk score." />
            <Note title="Dedupe" body="Asset + title + vector fingerprints remove repeat findings before the queue is counted." />
            <Note title="SLA" body="Critical 7 days, high 14, medium 30, low 90; overdue and due-soon are surfaced against today." />
          </div>
        </section>
      </main>

      <footer><span>TypeScript · React · Vite · Vitest</span><span>Reference implementation for Bastion Security</span></footer>
    </div>
  );
}

function Metric({ label, value, tone = "default" }: { label: string; value: string; tone?: "default" | "alert" | "blue" | "green" }) {
  return <div className={`metric ${tone}`}><span>{label}</span><strong>{value}</strong></div>;
}

function Note({ title, body }: { title: string; body: string }) {
  return <div className="note"><strong>{title}</strong><p>{body}</p></div>;
}

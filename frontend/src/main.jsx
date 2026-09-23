import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Shield, LayoutDashboard, Search, FolderOpen, Dna, Globe2,
  Network, FileText, Settings, Upload, AlertTriangle, CheckCircle2,
  XCircle, Activity, ChevronRight, Server, Link2, Mail, LockKeyhole
} from "lucide-react";
import "./styles.css";

const demo = {
  score: 82,
  classification: "HIGH RISK",
  sender: "support@secure-payments.example",
  subject: "Urgent: Verify your account",
  authentication: { spf: "PASS", dkim: "FAIL", dmarc: "FAIL" },
  ips: ["185.91.24.17", "104.21.62.9"],
  domains: ["secure-payments.example", "login-check.example"],
  urls: ["https://login-check.example/verify"],
  locations: [
    { name: "Frankfurt, Germany", ip: "185.91.24.17" },
    { name: "Amsterdam, Netherlands", ip: "104.21.62.9" }
  ],
  reasons: [
    "DKIM signature validation failed",
    "DMARC policy did not pass",
    "Sender domain differs from referenced organisation",
    "Credential harvesting language detected"
  ]
};

function Sidebar({ page, setPage }) {
  const items = [
    ["dashboard", "Dashboard", LayoutDashboard],
    ["analyze", "Analyze Email", Search],
    ["cases", "Cases", FolderOpen],
    ["ioc", "IOC Explorer", Dna],
    ["geo", "Geo Intelligence", Globe2],
    ["graph", "Infrastructure", Network],
    ["campaigns", "Campaigns", Activity],
    ["reports", "Reports", FileText],
  ];
  return <aside className="sidebar">
    <div className="brand"><div className="brandmark"><Shield size={21}/></div><div><b>Email_sec</b><span>THREAT INTELLIGENCE</span></div></div>
    <nav>{items.map(([id,label,Icon]) =>
      <button key={id} className={page===id ? "nav active":"nav"} onClick={()=>setPage(id)}><Icon size={18}/><span>{label}</span></button>
    )}</nav>
    <div className="sidebar-bottom">
      <button className="nav"><Settings size={18}/><span>Settings</span></button>
      <div className="connection"><span className="dot"></span><div><b>System Online</b><small>API services connected</small></div></div>
    </div>
  </aside>
}

function Header({title}) {
  return <header className="header"><div><p className="eyebrow">SECURITY OPERATIONS</p><h1>{title}</h1></div><div className="header-right"><span className="status"><span className="dot"/> LIVE</span><span className="analyst">Analyst <b>●</b></span></div></header>
}

function ThreatScore({score=demo.score}) {
  const r = 48, c = 2*Math.PI*r, offset = c - (score/100)*c;
  return <div className="score-card">
    <div className="score-ring"><svg viewBox="0 0 120 120"><circle className="ring-bg" cx="60" cy="60" r={r}/><circle className="ring-value" cx="60" cy="60" r={r} strokeDasharray={c} strokeDashoffset={offset}/></svg><div className="score-number"><strong>{score}</strong><span>/100</span></div></div>
    <div><p className="eyebrow">THREAT SCORE</p><h2 className="danger">HIGH RISK</h2><p className="muted">Multiple suspicious indicators detected</p></div>
  </div>
}

function AuthCard() {
  const rows = [["SPF",demo.authentication.spf],["DKIM",demo.authentication.dkim],["DMARC",demo.authentication.dmarc]];
  return <section className="panel"><div className="panel-title"><div><p className="eyebrow">EMAIL SECURITY</p><h3>Authentication</h3></div><LockKeyhole size={19}/></div>
    {rows.map(([k,v])=><div className="auth-row" key={k}><span>{k}</span><b className={v==="PASS"?"pass":"fail"}>{v==="PASS"?<CheckCircle2 size={17}/>:<XCircle size={17}/>} {v}</b></div>)}
  </section>
}

function IocCard() {
  return <section className="panel"><div className="panel-title"><div><p className="eyebrow">EXTRACTED</p><h3>Indicators of Compromise</h3></div><Dna size={19}/></div>
    <div className="ioc-grid"><div><b>{demo.ips.length}</b><span>IP addresses</span></div><div><b>{demo.domains.length}</b><span>Domains</span></div><div><b>{demo.urls.length}</b><span>URLs</span></div></div>
    <div className="ioc-list">{demo.domains.map(x=><div key={x}><span className="tag">DOMAIN</span><code>{x}</code><AlertTriangle size={15}/></div>)}</div>
  </section>
}

function RouteGraph() {
  return <section className="panel route"><div className="panel-title"><div><p className="eyebrow">MAIL ROUTE</p><h3>Infrastructure Path</h3></div><Network size={19}/></div>
    <div className="route-line">
      <div className="node"><Mail/><b>Sender</b><span>support@secure-payments</span></div><ChevronRight className="arrow"/>
      <div className="node"><Server/><b>185.91.24.17</b><span>Frankfurt, DE</span></div><ChevronRight className="arrow"/>
      <div className="node"><Server/><b>104.21.62.9</b><span>Amsterdam, NL</span></div><ChevronRight className="arrow"/>
      <div className="node"><Mail/><b>Recipient</b><span>target mailbox</span></div>
    </div>
  </section>
}

function Dashboard({setPage}) {
  return <><Header title="Threat Overview"/>
    <div className="content">
      <div className="hero-grid"><ThreatScore/><div className="metric"><span>IOCs EXTRACTED</span><strong>17</strong><small>IPs · Domains · URLs</small></div><div className="metric"><span>AUTHENTICATION</span><strong>1 / 3</strong><small>checks passed</small></div><div className="metric"><span>ROUTE HOPS</span><strong>4</strong><small>observed infrastructure</small></div></div>
      <div className="two-col"><AuthCard/><section className="panel"><div className="panel-title"><div><p className="eyebrow">EXPLAINABLE AI</p><h3>Why was it flagged?</h3></div><AlertTriangle size={19}/></div>{demo.reasons.map((r,i)=><div className="reason" key={r}><span>{String(i+1).padStart(2,"0")}</span>{r}</div>)}</section></div>
      <RouteGraph/><div className="two-col"><IocCard/><section className="panel"><div className="panel-title"><div><p className="eyebrow">CASE SUMMARY</p><h3>Suspicious Email</h3></div><FileText size={19}/></div><div className="email-meta"><span>FROM</span><b>{demo.sender}</b><span>SUBJECT</span><b>{demo.subject}</b><span>CLASSIFICATION</span><b className="danger">HIGH RISK</b></div><button className="primary" onClick={()=>setPage("analyze")}>Open Investigation <ChevronRight size={16}/></button></section></div>
    </div>
  </>
}

function Analyze({setPage}) {
  const [file,setFile] = useState(null);
  const [analysed,setAnalysed] = useState(false);
  return <><Header title="Analyze Email"/><div className="content narrow">
    {!analysed ? <section className="upload-panel"><div className="upload-icon"><Upload size={30}/></div><h2>Upload a suspicious email</h2><p>Drop an <b>.eml</b> file here or browse your device.</p><label className="dropzone">{file ? <><CheckCircle2 size={28}/><b>{file.name}</b><span>Ready for analysis</span></> : <><Upload size={28}/><b>Choose .eml file</b><span>Raw email or exported message</span></>}<input type="file" accept=".eml,message/rfc822" onChange={e=>setFile(e.target.files?.[0])}/></label>{file && <button className="primary big" onClick={()=>setAnalysed(true)}>Analyze Email <Search size={17}/></button>}<div className="feature-row"><span>✓ Header forensics</span><span>✓ SPF / DKIM / DMARC</span><span>✓ IOC extraction</span><span>✓ Threat scoring</span></div></section> : <div className="analysis-result"><div className="processing"><CheckCircle2/> Analysis complete</div><ThreatScore/><AuthCard/><button className="primary big" onClick={()=>setPage("dashboard")}>View Full Investigation <ChevronRight size={17}/></button></div>}
  </div></>
}

function Generic({title, label, text}) {
 return <><Header title={title}/><div className="content"><section className="panel empty-state"><div className="empty-icon"><Activity size={27}/></div><p className="eyebrow">{label}</p><h2>{text}</h2><p className="muted">This module is ready for backend integration. The visual system and navigation are already wired for the MVP.</p></section></div></>
}

function App() {
 const [page,setPage] = useState("dashboard");
 const pages = {
   dashboard:<Dashboard setPage={setPage}/>,
   analyze:<Analyze setPage={setPage}/>,
   cases:<Generic title="Cases" label="INVESTIGATION CASES" text="Manage email investigations"/>,
   ioc:<Generic title="IOC Explorer" label="INDICATORS OF COMPROMISE" text="Inspect extracted IPs, domains and URLs"/>,
   geo:<Generic title="Geo Intelligence" label="PROBABLE INFRASTRUCTURE" text="Map suspicious infrastructure locations"/>,
   graph:<Generic title="Infrastructure" label="CORRELATION GRAPH" text="Explore email → domain → IP relationships"/>,
   campaigns:<Generic title="Campaigns" label="CAMPAIGN CORRELATION" text="Group recurring infrastructure and indicators"/>,
   reports:<Generic title="Reports" label="FORENSIC EVIDENCE" text="Generate structured investigation reports"/>
 };
 return <div className="app"><Sidebar page={page} setPage={setPage}/><main>{pages[page]}</main></div>
}
createRoot(document.getElementById("root")).render(<App/>);
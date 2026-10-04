
import React,{useState} from "react";
import {createRoot} from "react-dom/client";
import "./style.css";

const API="";
const nav=[["Overview","◈"],["Investigate","⌁"],["Cases","▦"],["Threat Graph","◎"],["IOC Center","⌕"],["Reports","▤"]];

function App(){
 const [tab,setTab]=useState("Overview"),[file,setFile]=useState(null),[d,setD]=useState(null),[cases,setCases]=useState([]),[busy,setBusy]=useState(false);
 async function analyze(){
   if(!file)return alert("Select an .eml file first");
   setBusy(true);
   try{
    const fd=new FormData();fd.append("file",file);
    const r=await fetch(API+"/api/analyze",{method:"POST",body:fd});
    const raw=await r.text();
    let x={};
    try{x=raw?JSON.parse(raw):{};}catch(_){throw Error("Backend returned invalid response. Check the FastAPI terminal.");}
    if(!r.ok)throw Error(x.error||x.detail||("Backend error: HTTP "+r.status));
    setD(x);setCases(c=>[x,...c].slice(0,20));setTab("Investigate");
   }catch(e){alert(e.message)}finally{setBusy(false)}
 }
 return <div className="shell">
  <aside className="sidebar">
   <div className="brand"><div className="brandmark">S</div><div><b>SENTINEL<span>AI</span></b><small>CYBER FORENSICS PLATFORM</small></div></div>
   <div className="workspace"><span className="liveDot"/> SOC WORKSPACE <em>LIVE</em></div>
   <nav>{nav.map(([x,icon])=><button className={tab===x?"active":""} onClick={()=>setTab(x)}><i>{icon}</i>{x}{x==="Cases"&&cases.length?<strong>{cases.length}</strong>:null}</button>)}</nav>
   <div className="sideBottom"><div className="engine"><span className="pulse"/>Detection engine online</div><small>AI • Forensics • Threat Intelligence<br/>Correlation • Evidence</small></div>
  </aside>

  <main>
   <header className="topbar">
    <div><div className="crumb">SECURITY OPERATIONS CENTER / <b>{tab.toUpperCase()}</b></div><h1>{tab==="Overview"?"Threat Intelligence Overview":tab}</h1><p>AI-powered email threat detection, geolocation and forensic intelligence</p></div>
    <div className="topActions"><span className="system"><i/>ALL SYSTEMS OPERATIONAL</span><div className="avatar">SA</div></div>
   </header>

   {tab==="Overview"&&<Overview d={d} cases={cases} file={file} setFile={setFile} analyze={analyze} busy={busy}/>}
   {tab==="Investigate"&&<Investigate d={d}/>}
   {tab==="Cases"&&<Cases cases={cases}/>}
   {tab==="Threat Graph"&&<Graph d={d}/>}
   {tab==="IOC Center"&&<IOCs d={d}/>}
   {tab==="Reports"&&<Reports file={file}/>}
  </main>
 </div>
}

function Overview({d,cases,file,setFile,analyze,busy}){
 const risk=d?.risk_score??0;
 const critical=cases.filter(x=>x.risk_level==="Critical").length;
 const high=cases.filter(x=>x.risk_level==="High").length;
 return <div className="page">
  <section className="hero2">
   <div className="heroCopy">
    <div className="eyebrow"><span/> EMAIL THREAT ANALYSIS</div>
    <h2>Turn suspicious emails into<br/><span>actionable intelligence.</span></h2>
    <p>Parse technical headers, validate authentication, extract indicators, identify impersonation and build an explainable forensic picture of the attack.</p>
    <div className="dropzone">
     <div className="uploadIcon">↑</div>
     <div className="dropText"><b>{file?file.name:"No email selected"}</b><small>{file?"Ready for forensic analysis":"Select a suspicious .eml file from your computer"}</small></div>
     <input id="emailFile" className="fileInput" type="file" accept=".eml" onChange={e=>setFile(e.target.files[0])}/>
     <label htmlFor="emailFile" className="chooseBtn">CHOOSE FILE</label>
     <button onClick={analyze}>{busy?"ANALYZING":"START INVESTIGATION"} <span>→</span></button>
    </div>
   </div>
   <div className="heroVisual">
    <div className="radial" style={{"--p":risk+"%"}}><div><b>{d?risk:"—"}</b><small>/ 100</small><label>RISK SCORE</label></div></div>
    <div className="ringLabel"><span className={risk>=60?"danger":"safe"}>{d?d.risk_level.toUpperCase():"READY"}</span><small>{d?"Threat assessment":"Awaiting evidence"}</small></div>
   </div>
  </section>

  <section className="metricRow">
   <Metric icon="⌁" label="INVESTIGATIONS" value={cases.length||"00"} note="Current session" />
   <Metric icon="!" label="CRITICAL THREATS" value={critical||"00"} note="Immediate attention" danger/>
   <Metric icon="◉" label="HIGH RISK" value={high||"00"} note="Priority cases"/>
   <Metric icon="⌕" label="IOCs EXTRACTED" value={d?.iocs?.length??"00"} note="IPs • URLs • Domains"/>
   <Metric icon="◈" label="ML CONFIDENCE" value={d?Math.round(d.ml.confidence*100)+"%":"—"} note="Explainable baseline"/>
  </section>

  <div className="dashGrid">
   <section className="glass wide"><SectionHead title="Threat posture" sub="Current investigation intelligence"/>
    <div className="posture">
      <div className="bars"><Bar label="Critical" value={critical} total={Math.max(cases.length,1)}/><Bar label="High" value={high} total={Math.max(cases.length,1)}/><Bar label="Medium" value={cases.filter(x=>x.risk_level==="Medium").length} total={Math.max(cases.length,1)}/><Bar label="Low" value={cases.filter(x=>x.risk_level==="Low").length} total={Math.max(cases.length,1)}/></div>
      <div className="miniGraph"><div className="gridlines"/><svg viewBox="0 0 420 120"><polyline points="0,98 45,82 90,91 135,54 180,67 225,35 270,58 315,28 360,42 420,15" fill="none" stroke="currentColor" strokeWidth="3"/><polyline points="0,118 45,82 90,91 135,54 180,67 225,35 270,58 315,28 360,42 420,15 420,120" fill="currentColor" opacity=".07"/></svg><small>Threat activity • analysis trend</small></div>
    </div>
   </section>

   <section className="glass"><SectionHead title="Authentication" sub="Email trust signals"/>
    <div className="authDash"><AuthDot name="SPF" value={d?.authentication?.spf}/><AuthDot name="DKIM" value={d?.authentication?.dkim}/><AuthDot name="DMARC" value={d?.authentication?.dmarc}/></div>
    <div className="authFoot"><span>Authentication health</span><b>{d?"3 checks completed":"Awaiting email"}</b></div>
   </section>

   <section className="glass"><SectionHead title="Investigation coverage" sub="Detection capabilities"/>
    <div className="coverage"><Cov n="Header forensics" ok/><Cov n="Phishing language" ok/><Cov n="Sender spoofing" ok/><Cov n="IOC extraction" ok/><Cov n="Infrastructure" ok/><Cov n="Evidence hashing" ok/></div>
   </section>

   <section className="glass wide"><SectionHead title="Recent investigations" sub="Latest analyzed evidence"/>{cases.length?<table><thead><tr><th>CASE</th><th>SUBJECT</th><th>RISK</th><th>VERDICT</th><th>STATUS</th></tr></thead><tbody>{cases.slice(0,5).map(x=><tr><td className="mono">{x.case_id}</td><td>{x.subject||"No subject"}</td><td><span className={"riskPill "+x.risk_level.toLowerCase()}>{x.risk_score} • {x.risk_level}</span></td><td>{x.ml.label}</td><td><span className="statusPill">Investigating</span></td></tr>)}</tbody></table>:<div className="empty">Analyze an email to populate investigation activity.</div>}</section>

   <section className="glass"><SectionHead title="Analysis pipeline" sub="Evidence processing stages"/><div className="pipeline2">{["INGEST","HEADERS","AUTH","AI / NLP","IOC","CORRELATE","RISK","REPORT"].map((x,i)=><div><b>{String(i+1).padStart(2,"0")}</b><span>{x}</span></div>)}</div></section>
  </div>
 </div>
}
function Metric({icon,label,value,note,danger}){return <div className={"metric "+(danger?"metricDanger":"")}><div className="metricIcon">{icon}</div><div><small>{label}</small><strong>{value}</strong><span>{note}</span></div></div>}
function SectionHead({title,sub}){return <div className="sectionHead"><div><h3>{title}</h3><p>{sub}</p></div><span>•••</span></div>}
function Bar({label,value,total}){let pct=Math.round(value/total*100);return <div className="bar"><div><span>{label}</span><b>{value}</b></div><i><em style={{width:Math.max(pct,value?8:2)+"%"}}/></i></div>}
function AuthDot({name,value}){let v=value||"unknown";return <div className="authItem"><div className={"authCircle "+v}>{value==="pass"?"✓":value==="fail"?"!":"?"}</div><b>{name}</b><span className={v}>{v.toUpperCase()}</span></div>}
function Cov({n,ok}){return <div><span>{ok?"✓":"–"}</span>{n}</div>}

function Investigate({d}){
 if(!d)return <div className="glass emptyPage"><div className="bigEmpty">⌁</div><h2>No investigation loaded</h2><p>Upload a suspicious .eml file from Overview to begin forensic analysis.</p></div>;
 return <div className="page"><div className="metricRow"><Metric label="RISK SCORE" value={d.risk_score+"/100"} note={d.risk_level}/><Metric label="AI VERDICT" value={d.ml.label} note={Math.round(d.ml.confidence*100)+"% confidence"}/><Metric label="URLS" value={d.urls.length} note="Extracted"/><Metric label="IP INDICATORS" value={d.ips.length} note="Observed"/><Metric label="ATTACHMENTS" value={d.attachments.length} note="SHA-256"/></div>
 <div className="dashGrid"><section className="glass"><SectionHead title="Authentication" sub="Sender trust validation"/><div className="authDash"><AuthDot name="SPF" value={d.authentication.spf}/><AuthDot name="DKIM" value={d.authentication.dkim}/><AuthDot name="DMARC" value={d.authentication.dmarc}/></div></section>
 <section className="glass"><SectionHead title="Email identity" sub="Origin and routing evidence"/><div className="identity"><p><label>FROM</label><b>{d.from||"—"}</b></p><p><label>REPLY-TO</label><b>{d.reply_to||"—"}</b></p><p><label>SUBJECT</label><b>{d.subject||"—"}</b></p></div></section>
 <section className="glass wide"><SectionHead title="Explainable findings" sub="Why the engine assigned this risk level"/>{d.findings.map(f=><div className="finding2"><span className={f.severity}>{f.severity}</span><div><b>{f.title}</b><p>{f.detail}</p></div><strong>!</strong></div>)}</section>
 <section className="glass"><SectionHead title="IP intelligence" sub="Infrastructure enrichment"/>{d.geolocation.length?d.geolocation.map(x=><div className="geo2"><div className="geoPin">⌖</div><div><b>{x.ip}</b><span>{x.country} • {x.city}</span><small>{x.isp}</small></div></div>):<div className="empty">No IP observed.</div>}</section>
 <section className="glass"><SectionHead title="Forensic timeline" sub="Received header reconstruction"/>{d.timeline.length?d.timeline.map(x=><div className="timeline2"><i/ ><div><b>HOP {x.step}</b><p>{x.event}</p></div></div>):<div className="empty">No Received chain.</div>}</section></div></div>
}

function Cases({cases}){return <div className="page"><section className="glass"><SectionHead title="Investigation cases" sub="Evidence-driven case management"/>{cases.length?<table><thead><tr><th>CASE</th><th>SUBJECT</th><th>RISK</th><th>AI VERDICT</th><th>STATUS</th></tr></thead><tbody>{cases.map(x=><tr><td className="mono">{x.case_id}</td><td>{x.subject}</td><td><span className={"riskPill "+x.risk_level.toLowerCase()}>{x.risk_score} • {x.risk_level}</span></td><td>{x.ml.label}</td><td><span className="statusPill">Investigating</span></td></tr>)}</tbody></table>:<div className="empty">No cases yet. Analyze an email first.</div>}</section></div>}

function Graph({d}){return <div className="page"><section className="glass"><SectionHead title="Threat infrastructure graph" sub="Email → identity → infrastructure correlation"/>{!d?<div className="empty">Analyze an email first.</div>:<div className="threatCanvas"><div className="graphCenter"><b>EMAIL</b><small>Investigation</small></div>{d.graph.nodes.slice(1,9).map((n,i)=><div className={"thNode t"+i}><span>{n.type}</span><b>{n.label}</b></div>)}<div className="graphLines"/><div className="graphLegend">CORRELATION-READY • SENDER • DOMAIN • IP • URL</div></div>}</section></div>}

function IOCs({d}){return <div className="page"><section className="glass"><SectionHead title="IOC intelligence center" sub="Indicators extracted from current evidence"/>{!d?<div className="empty">Analyze an email first.</div>:<div className="iocBig">{d.iocs.map(x=><div className="iocCard"><span>{x.type}</span><code>{x.value}</code><small>Extracted from evidence</small></div>)}</div>}</section></div>}

function Reports({file}){return <div className="page"><section className="glass reportHero"><div className="reportIcon">▤</div><div><h2>Forensic Investigation Report</h2><p>Generate an evidence-focused report containing authentication, findings, IOCs, infrastructure and timeline.</p>{file?<button onClick={async()=>{let f=new FormData();f.append("file",file);let r=await fetch("/api/report",{method:"POST",body:f});let h=await r.text();let w=window.open();w.document.write(h)}}>GENERATE REPORT ↗</button>:<span className="hint">Select an .eml file from Overview first.</span>}</div></section></div>}

createRoot(document.getElementById("root")).render(<App/>);

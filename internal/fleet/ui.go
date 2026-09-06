package fleet

import (
	"html/template"
	"net/http"
	"strings"
	"time"
)

// indexPage renders the fleet inventory: summary counts plus a table of
// every known Sentinel (desired vs actual policy and sync state included,
// Prompt 14A), polling the JSON API every few seconds. No "Drifted" summary
// count is shown -- see PolicyState's doc comment for why.
var indexPage = template.Must(template.New("index").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Airlock Fleet</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0b1220;color:#e5e7eb;margin:0;padding:28px 32px}
h1{font-size:20px;letter-spacing:.04em;margin:0 0 4px;text-transform:uppercase}
.sub{color:#94a3b8;font-size:13px;margin-bottom:20px}
.stats{display:flex;gap:14px;margin-bottom:22px}
.stat{background:#101b2b;border:1px solid #28364a;border-radius:10px;padding:14px 20px;min-width:110px}
.stat .n{font-size:26px;font-weight:750}
.stat .l{font-size:11px;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em}
.stat.active .n{color:#5eead4}
.stat.offline .n{color:#fca5a5}
.stat.drift .n{color:#fde68a}
.stat.revoked .n{color:#fca5a5}
table{width:100%;border-collapse:collapse;background:#101b2b;border:1px solid #28364a;border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 14px;font-size:13px;border-top:1px solid #1e293b}
th{color:#94a3b8;font-size:11px;text-transform:uppercase;letter-spacing:.05em;border-top:none}
tr:hover td{background:#131f33}
a{color:#93c5fd;text-decoration:none}
.badge{border-radius:999px;padding:2px 9px;font-size:11px;font-weight:800;letter-spacing:.03em}
.badge.active{background:#052e2b;color:#99f6e4;border:1px solid #0f766e}
.badge.offline{background:#3b1318;color:#fecaca;border:1px solid #991b1b}
.badge.sync{background:#052e2b;color:#99f6e4;border:1px solid #0f766e}
.badge.drift{background:#3a2c12;color:#fde68a;border:1px solid #854d0e}
.badge.fail{background:#3b1318;color:#fecaca;border:1px solid #991b1b}
.badge.unmanaged{background:#1e293b;color:#94a3b8;border:1px solid #334155}
.badge.auth{background:#052e2b;color:#99f6e4;border:1px solid #0f766e}
.badge.unauth{background:#3a2c12;color:#fde68a;border:1px solid #854d0e}
.badge.revoked{background:#3b1318;color:#fecaca;border:1px solid #991b1b}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.empty{padding:30px;text-align:center;color:#94a3b8}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin:26px 0 10px}
</style></head>
<body>
<h1>Airlock Fleet</h1>
<div class="sub">Control plane for Sentinel inventory, health, trust, and desired-state policy. Not in the filesystem-policy decision path -- Sentinels enforce locally whether or not this page can reach them, and a revoked Sentinel keeps protecting its repository.</div>
<div class="stats">
  <div class="stat active"><div class="n" id="active">-</div><div class="l">Active</div></div>
  <div class="stat offline"><div class="n" id="offline">-</div><div class="l">Offline</div></div>
  <div class="stat drift"><div class="n" id="drifted">-</div><div class="l">Drifted</div></div>
  <div class="stat revoked"><div class="n" id="revoked">-</div><div class="l">Revoked</div></div>
</div>
<div id="table-wrap"></div>
<h2>Recent fleet alerts</h2>
<div class="sub">Metadata reported by Sentinels, including activity buffered while they were disconnected. Raw evidence stays on each Sentinel's own machine.</div>
<div id="alerts-wrap"></div>
<script>
function esc(v){return String(v==null?"":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];});}
function ago(iso){if(!iso)return "never";var d=new Date(iso);if(isNaN(d.getTime()))return "never";var s=Math.max(0,Math.round((Date.now()-d.getTime())/1000));if(s<60)return s+"s ago";if(s<3600)return Math.round(s/60)+"m ago";if(s<86400)return Math.round(s/3600)+"h ago";return Math.round(s/86400)+"d ago";}
function policyLabel(id,version){if(!id)return "-";return version?id+" v"+version:id;}
function syncBadge(state){
  if(!state)return "<span class='badge unmanaged'>UNMANAGED</span>";
  var cls=state==="IN_SYNC"?"sync":(state==="RECONCILE_FAILED"?"fail":"drift");
  return "<span class='badge "+cls+"'>"+state.replace("_"," ")+"</span>";
}
function identityBadge(state){
  if(state==="REVOKED")return "<span class='badge revoked'>REVOKED</span>";
  if(state==="AUTHENTICATED")return "<span class='badge auth'>AUTHENTICATED</span>";
  return "<span class='badge unauth'>UNAUTHENTICATED</span>";
}
function render(d){
  document.getElementById("active").textContent=d.active;
  document.getElementById("offline").textContent=d.offline;
  document.getElementById("drifted").textContent=d.drifted;
  document.getElementById("revoked").textContent=d.revoked;
  var wrap=document.getElementById("table-wrap");
  if(!d.sentinels||!d.sentinels.length){wrap.innerHTML="<div class='empty'>No Sentinels enrolled yet. Start one with: airlock sentinel --repo . --fleet http://&lt;this-host&gt; --background</div>";return;}
  var rows=d.sentinels.map(function(sv){
    return "<tr><td><a href='/fleet/sentinels/"+encodeURIComponent(sv.sentinel_id)+"'>"+esc(sv.sentinel_id.slice(0,8))+"</a></td>"+
      "<td><span class='badge "+(sv.health==="ACTIVE"?"active":"offline")+"'>"+sv.health+"</span></td>"+
      "<td>"+identityBadge(sv.identity)+"</td>"+
      "<td class='mono'>"+esc(sv.repo_path||"-")+"</td>"+
      "<td>"+esc(policyLabel(sv.desired_policy_id,sv.desired_policy_version))+"</td>"+
      "<td>"+esc(policyLabel(sv.policy_id,sv.policy_version))+"</td>"+
      "<td>"+syncBadge(sv.policy_state)+"</td>"+
      "<td>"+esc(sv.signature_state||"-")+"</td>"+
      "<td>"+ago(sv.last_heartbeat)+"</td></tr>";
  }).join("");
  wrap.innerHTML="<table><tr><th>Sentinel</th><th>Status</th><th>Identity</th><th>Repository</th><th>Desired</th><th>Actual</th><th>Sync</th><th>Signature</th><th>Heartbeat</th></tr>"+rows+"</table>";
}
function renderAlerts(list){
  var wrap=document.getElementById("alerts-wrap");
  if(!list||!list.length){wrap.innerHTML="<div class='empty'>No alerts reported yet.</div>";return;}
  var rows=list.map(function(a){
    var cls=(a.type==="REVERT_FAILED"||a.type==="SIGNATURE_INVALID"||a.type==="DOWNGRADE_REJECTED"||a.type==="CREDENTIAL_REVOKED")?"fail":
            (a.type==="REVERTED"||a.type==="DENY"||a.type==="RECONCILE_FAILED")?"drift":"sync";
    return "<tr><td>"+esc((a.sentinel_id||"").slice(0,8))+"</td>"+
      "<td class='mono'>"+esc(a.repo_path||"-")+"</td>"+
      "<td><span class='badge "+cls+"'>"+esc(String(a.type).replace(/_/g," "))+"</span></td>"+
      "<td class='mono'>"+esc(a.path||a.summary||"-")+"</td>"+
      "<td>"+ago(a.at)+"</td></tr>";
  }).join("");
  wrap.innerHTML="<table><tr><th>Sentinel</th><th>Repository</th><th>Event</th><th>Detail</th><th>When</th></tr>"+rows+"</table>";
}
function load(){
  fetch("/api/fleet/sentinels",{cache:"no-store"}).then(function(r){return r.json();}).then(render).catch(function(){});
  fetch("/api/fleet/alerts?limit=25",{cache:"no-store"}).then(function(r){return r.json();}).then(renderAlerts).catch(function(){});
}
load();setInterval(load,3000);
</script>
</body></html>`))

var detailPage = template.Must(template.New("detail").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Sentinel {{.Record.SentinelID}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0b1220;color:#e5e7eb;margin:0;padding:28px 32px}
a{color:#93c5fd;text-decoration:none}
h1{font-size:18px;margin:16px 0 18px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin:24px 0 10px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.field{background:#101b2b;border:1px solid #28364a;border-radius:10px;padding:12px 14px}
.k{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#94a3b8}
.v{font-size:14px;font-weight:650;margin-top:4px;word-break:break-all}
.v.err{color:#fca5a5;font-weight:500;font-size:12px}
.badge{border-radius:999px;padding:2px 9px;font-size:11px;font-weight:800}
.badge.active{background:#052e2b;color:#99f6e4;border:1px solid #0f766e}
.badge.offline{background:#3b1318;color:#fecaca;border:1px solid #991b1b}
.badge.sync{background:#052e2b;color:#99f6e4;border:1px solid #0f766e}
.badge.drift{background:#3a2c12;color:#fde68a;border:1px solid #854d0e}
.badge.fail{background:#3b1318;color:#fecaca;border:1px solid #991b1b}
.badge.unmanaged{background:#1e293b;color:#94a3b8;border:1px solid #334155}
.badge.auth{background:#052e2b;color:#99f6e4;border:1px solid #0f766e}
.badge.unauth{background:#3a2c12;color:#fde68a;border:1px solid #854d0e}
.badge.revoked{background:#3b1318;color:#fecaca;border:1px solid #991b1b}
.note{background:#101b2b;border:1px solid #28364a;border-left:3px solid #854d0e;border-radius:8px;padding:11px 14px;font-size:12px;color:#cbd5e1;margin-top:10px}
.badge.hist{background:#1e293b;color:#cbd5e1;border:1px solid #475569}
.sub{color:#94a3b8;font-size:13px;margin-bottom:14px}
.stats{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap}
.stat{background:#101b2b;border:1px solid #28364a;border-radius:10px;padding:10px 16px;min-width:92px}
.stat .n{font-size:20px;font-weight:750}
.stat .l{font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;background:#101b2b;border:1px solid #28364a;border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;font-size:12.5px;border-top:1px solid #1e293b;white-space:nowrap}
th{color:#94a3b8;font-size:10px;text-transform:uppercase;letter-spacing:.05em;border-top:none}
tr:hover td{background:#131f33}
.empty{padding:24px;text-align:center;color:#94a3b8}
.tablewrap{overflow-x:auto}
@media (max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:600px){.grid{grid-template-columns:1fr}}
.assign{background:#101b2b;border:1px solid #28364a;border-radius:10px;padding:14px;display:flex;gap:8px;align-items:end;flex-wrap:wrap}
.assign label{display:flex;flex-direction:column;font-size:11px;color:#94a3b8;gap:4px}
.assign input{background:#0b1220;border:1px solid #334155;border-radius:6px;color:#e5e7eb;padding:6px 8px;font-size:13px}
.assign button{background:#1d4ed8;color:#fff;border:0;border-radius:6px;padding:7px 14px;font-size:13px;cursor:pointer}
.msg{margin-top:8px;font-size:12px;color:#94a3b8}
</style></head>
<body>
<a href="/">&larr; Fleet inventory</a>
<h1>Sentinel {{.Record.SentinelID}} <span class="badge {{if eq .Health "ACTIVE"}}active{{else}}offline{{end}}">{{.Health}}</span>
<span class="badge {{if eq .Identity "AUTHENTICATED"}}auth{{else if eq .Identity "REVOKED"}}revoked{{else}}unauth{{end}}">{{.Identity}}</span>
{{if .PolicyState}}<span class="badge {{if eq .PolicyState "IN_SYNC"}}sync{{else if eq .PolicyState "DRIFTED"}}drift{{else if eq .PolicyState "RECONCILING"}}drift{{else}}fail{{end}}">{{.PolicyState}}</span>{{end}}</h1>
{{if eq .Identity "REVOKED"}}<div class="note"><strong>This Sentinel's Fleet credential is revoked.</strong> It can no longer participate in Fleet.
It continues governing {{.Record.RepoPath}} locally, enforcing its last-known-good policy. Revocation removes a Sentinel from the
control plane; it is not an instruction to stop protecting a repository.{{if .Record.RevokedReason}} Reason: {{.Record.RevokedReason}}{{end}}</div>{{end}}
<div class="grid">
  <div class="field"><div class="k">Sentinel ID</div><div class="v">{{.Record.SentinelID}}</div></div>
  <div class="field"><div class="k">Machine ID</div><div class="v">{{.Record.MachineID}}</div></div>
  <div class="field"><div class="k">Repository</div><div class="v">{{.Record.RepoPath}}</div></div>
  <div class="field"><div class="k">Hostname</div><div class="v">{{.Record.Hostname}}</div></div>
  <div class="field"><div class="k">Platform</div><div class="v">{{.Record.Platform}}</div></div>
  <div class="field"><div class="k">Sentinel version</div><div class="v">{{.Record.SentinelVersion}}</div></div>
  <div class="field"><div class="k">Current session</div><div class="v">{{.Record.SessionID}}</div></div>
  <div class="field"><div class="k">Enrolled</div><div class="v">{{.Record.EnrolledAt}}</div></div>
  <div class="field"><div class="k">Started</div><div class="v">{{.Record.StartedAt}}</div></div>
  <div class="field"><div class="k">Last heartbeat</div><div class="v">{{.Record.LastHeartbeat}}</div></div>
  <div class="field"><div class="k">Last event</div><div class="v">{{if .Record.LastEventAt}}{{.Record.LastEventAt}}{{else}}-{{end}}</div></div>
  <div class="field"><div class="k">Last reconciliation</div><div class="v">{{if .Record.LastReconcileAt}}{{.Record.LastReconcileAt}}{{else}}-{{end}}</div></div>
</div>

<h2>Policy</h2>
<div class="grid">
  <div class="field"><div class="k">Desired policy</div><div class="v">{{if .Record.DesiredPolicyID}}{{.Record.DesiredPolicyID}} v{{.Record.DesiredPolicyVersion}}{{else}}unmanaged{{end}}</div></div>
  <div class="field"><div class="k">Actual policy</div><div class="v">{{if .Record.PolicyID}}{{.Record.PolicyID}}{{if .Record.PolicyVersion}} v{{.Record.PolicyVersion}}{{end}}{{else}}-{{end}}</div></div>
  <div class="field"><div class="k">Sync state</div><div class="v">{{if .PolicyState}}{{.PolicyState}}{{else}}unmanaged{{end}}</div></div>
  <div class="field"><div class="k">Desired hash</div><div class="v">{{if .Record.DesiredPolicyHash}}{{.Record.DesiredPolicyHash}}{{else}}-{{end}}</div></div>
  <div class="field"><div class="k">Actual hash</div><div class="v">{{if .Record.PolicyHash}}{{.Record.PolicyHash}}{{else}}-{{end}}</div></div>
  <div class="field"><div class="k">Reconciliation error</div><div class="v{{if .PolicyStateError}} err{{end}}">{{if .PolicyStateError}}{{.PolicyStateError}}{{else}}-{{end}}</div></div>
</div>

<h2>Trust</h2>
<div class="grid">
  <div class="field"><div class="k">Identity</div><div class="v">{{.Identity}}</div></div>
  <div class="field"><div class="k">Policy signature</div><div class="v">{{if .Record.SignatureState}}{{.Record.SignatureState}}{{else}}-{{end}}</div></div>
  <div class="field"><div class="k">Policy signer</div><div class="v">{{if .Record.SignerKeyID}}{{.Record.SignerKeyID}}{{else}}-{{end}}</div></div>
  <div class="field"><div class="k">Credential issued</div><div class="v">{{if .Record.CredentialIssued}}yes{{else}}no{{end}}</div></div>
  <div class="field"><div class="k">Revoked at</div><div class="v">{{if .Record.RevokedAt}}{{.Record.RevokedAt}}{{else}}-{{end}}</div></div>
  <div class="field"><div class="k">Buffered reports</div><div class="v">{{.Record.BufferedReports}}</div></div>
</div>

<h2>Assign desired policy</h2>
<div class="assign">
  <label>Policy ID<input id="assign-id" type="text" value="{{.Record.DesiredPolicyID}}" placeholder="production"></label>
  <label>Version<input id="assign-version" type="number" min="1" style="width:80px"></label>
  <button type="button" onclick="assignPolicy()">Assign</button>
</div>
<div class="msg" id="assign-msg"></div>

<h2>Governance counters (current session)</h2>
<div class="grid">
  <div class="field"><div class="k">Allowed</div><div class="v">{{.Record.AllowCount}}</div></div>
  <div class="field"><div class="k">Denied</div><div class="v">{{.Record.DenyCount}}</div></div>
  <div class="field"><div class="k">Reverted</div><div class="v">{{.Record.RevertedCount}}</div></div>
  <div class="field"><div class="k">Revert failed</div><div class="v">{{.Record.RevertFailedCount}}</div></div>
</div>

<h2>Session history</h2>
<div class="sub" id="history-note">Every monitoring session this Sentinel has run. Restarting a Sentinel starts a new session and keeps the same identity &mdash; history is never erased by a restart. <strong>Raw evidence remains local to the Sentinel</strong>; Fleet keeps only this metadata.</div>
<div id="totals" class="stats"></div>
<div id="history-wrap"></div>
<script>
var sentinelID="{{.Record.SentinelID}}";
function escH(v){return String(v==null?"":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];});}
function agoH(iso){if(!iso)return "never";var d=new Date(iso);if(isNaN(d.getTime()))return "never";var s=Math.max(0,Math.round((Date.now()-d.getTime())/1000));if(s<60)return s+"s ago";if(s<3600)return Math.round(s/60)+"m ago";if(s<86400)return Math.round(s/3600)+"h ago";return Math.round(s/86400)+"d ago";}
function stamp(iso){if(!iso)return "—";var d=new Date(iso);return isNaN(d.getTime())?"—":d.toLocaleString();}
function sessionBadge(v){
  if(v.current)return "<span class='badge active'>CURRENT · ACTIVE</span>";
  if(v.status==="STOPPED")return "<span class='badge hist'>HISTORICAL · STOPPED</span>";
  return "<span class='badge drift'>HISTORICAL · INTERRUPTED</span>";
}
function renderHistory(d){
  var t=d.totals||{session_count:0,allow_count:0,deny_count:0,reverted_count:0,revert_failed_count:0};
  document.getElementById("totals").innerHTML=
    "<div class='stat'><div class='n'>"+t.session_count+"</div><div class='l'>Sessions</div></div>"+
    "<div class='stat'><div class='n'>"+t.allow_count+"</div><div class='l'>Allowed</div></div>"+
    "<div class='stat'><div class='n'>"+t.deny_count+"</div><div class='l'>Denied</div></div>"+
    "<div class='stat'><div class='n'>"+t.reverted_count+"</div><div class='l'>Reverted</div></div>"+
    "<div class='stat'><div class='n'>"+t.revert_failed_count+"</div><div class='l'>Revert failed</div></div>";
  var wrap=document.getElementById("history-wrap");
  if(!d.sessions||!d.sessions.length){wrap.innerHTML="<div class='empty'>No session history recorded yet.</div>";return;}
  var rows=d.sessions.map(function(v){
    var ended=v.stopped_at?stamp(v.stopped_at):(v.status==="INTERRUPTED"?"no clean stop reported":"—");
    return "<tr><td><a href='/fleet/sessions/"+encodeURIComponent(v.session_id)+"'>"+escH(v.session_id.slice(0,8))+"</a></td>"+
      "<td>"+sessionBadge(v)+"</td>"+
      "<td>"+escH(v.policy_id?(v.policy_version?v.policy_id+" v"+v.policy_version:v.policy_id):"—")+"</td>"+
      "<td>"+escH(v.signature_state||"—")+"</td>"+
      "<td>"+stamp(v.started_at)+"</td>"+
      "<td>"+escH(ended)+"</td>"+
      "<td>"+agoH(v.last_seen_at)+"</td>"+
      "<td>"+v.allow_count+" / "+v.deny_count+" / "+v.reverted_count+" / "+v.revert_failed_count+"</td></tr>";
  }).join("");
  wrap.innerHTML="<table><tr><th>Session</th><th>State</th><th>Policy enforced</th><th>Signature</th><th>Started</th><th>Ended</th><th>Last seen</th><th>Allow / Deny / Rev / Fail</th></tr>"+rows+"</table>";
  var r=d.retention;
  if(r&&r.enabled){
    document.getElementById("history-note").innerHTML+=" Fleet keeps the newest "+r.max_sessions_per_sentinel+" sessions per Sentinel; older <em>metadata</em> ages out without touching local evidence.";
  }
}
function loadHistory(){fetch("/api/fleet/sentinels/"+encodeURIComponent(sentinelID)+"/sessions",{cache:"no-store"}).then(function(r){return r.json();}).then(renderHistory).catch(function(){});}
loadHistory();setInterval(loadHistory,5000);
</script>
<script>
var assignURL="/api/fleet/sentinels/"+encodeURIComponent("{{.Record.SentinelID}}")+"/assign";
function assignPolicy(){
  var id=document.getElementById("assign-id").value.trim();
  var version=parseInt(document.getElementById("assign-version").value,10);
  var msg=document.getElementById("assign-msg");
  if(!id||!version){msg.textContent="Policy ID and a version number are required.";return;}
  fetch(assignURL,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({policy_id:id,version:version})})
    .then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(t);});return r.json();})
    .then(function(){msg.textContent="Assigned. It will take effect on the Sentinel's next heartbeat.";setTimeout(function(){location.reload();},1200);})
    .catch(function(e){msg.textContent="Assign failed: "+e.message;});
}
</script>
</body></html>`))

// sessionPage renders one historical or current governance session. It is
// deliberately explicit about two things an operator must not have to guess:
// where the authoritative evidence actually is, and what an INTERRUPTED
// session does and does not imply about local enforcement.
var sessionPage = template.Must(template.New("session").Funcs(template.FuncMap{
	"shortID": shortID,
}).Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Session {{.View.SessionID}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0b1220;color:#e5e7eb;margin:0;padding:28px 32px}
a{color:#93c5fd;text-decoration:none}
a:focus,button:focus{outline:2px solid #60a5fa;outline-offset:2px}
h1{font-size:18px;margin:16px 0 6px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8;margin:24px 0 10px}
.crumb{font-size:12px;color:#94a3b8;margin-bottom:6px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
.field{background:#101b2b;border:1px solid #28364a;border-radius:10px;padding:12px 14px}
.k{font-size:10px;text-transform:uppercase;letter-spacing:.07em;color:#94a3b8}
.v{font-size:14px;font-weight:650;margin-top:4px;word-break:break-all}
.badge{border-radius:999px;padding:2px 9px;font-size:11px;font-weight:800}
.badge.active{background:#052e2b;color:#99f6e4;border:1px solid #0f766e}
.badge.hist{background:#1e293b;color:#cbd5e1;border:1px solid #475569}
.badge.drift{background:#3a2c12;color:#fde68a;border:1px solid #854d0e}
.note{background:#101b2b;border:1px solid #28364a;border-left:3px solid #0f766e;border-radius:8px;padding:11px 14px;font-size:12px;color:#cbd5e1;margin:12px 0}
.note.warn{border-left-color:#854d0e}
table{width:100%;border-collapse:collapse;background:#101b2b;border:1px solid #28364a;border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;font-size:12.5px;border-top:1px solid #1e293b}
th{color:#94a3b8;font-size:10px;text-transform:uppercase;letter-spacing:.05em;border-top:none}
.empty{padding:22px;text-align:center;color:#94a3b8}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
@media (max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:600px){.grid{grid-template-columns:1fr}}
</style></head>
<body>
<div class="crumb"><a href="/">Fleet</a> &rsaquo; <a href="/fleet/sentinels/{{.View.SentinelID}}">Sentinel {{shortID .View.SentinelID}}</a> &rsaquo; Sessions &rsaquo; {{shortID .View.SessionID}}</div>
<h1>Session {{shortID .View.SessionID}}
{{if .View.Current}}<span class="badge active">CURRENT · ACTIVE</span>
{{else if eq .View.Status "STOPPED"}}<span class="badge hist">HISTORICAL · STOPPED</span>
{{else}}<span class="badge drift">HISTORICAL · INTERRUPTED</span>{{end}}</h1>

{{if eq .View.OwnerIdentity "REVOKED"}}<div class="note warn"><strong>This Sentinel's Fleet credential has been revoked.</strong>
It can no longer participate in Fleet, so this session will stop being updated here. <em>That is not the same as the Sentinel stopping.</em>
A revoked Sentinel keeps enforcing its last-known-good policy on its own machine, and its local evidence is untouched.
Fleet is recording the end of its own visibility, not the end of governance.</div>{{end}}

{{if eq .View.Status "INTERRUPTED"}}<div class="note warn"><strong>This session stopped reporting without a clean shutdown.</strong>
Fleet knows only that it stopped hearing from it &mdash; the process may have been killed, the machine may have slept, the network may have dropped,
or this Sentinel's Fleet credential may have been revoked. <em>This does not mean local governance stopped.</em> A Sentinel that cannot reach Fleet,
including a revoked one, keeps enforcing its last-known-good policy locally. No <code>stopped_at</code> is recorded, because none was ever reported.</div>{{end}}

<h2>Identity</h2>
<div class="grid">
  <div class="field"><div class="k">Session ID</div><div class="v mono">{{.View.SessionID}}</div></div>
  <div class="field"><div class="k">Sentinel ID</div><div class="v mono">{{.View.SentinelID}}</div></div>
  <div class="field"><div class="k">Machine ID</div><div class="v mono">{{if .View.MachineID}}{{.View.MachineID}}{{else}}—{{end}}</div></div>
  <div class="field"><div class="k">Repository</div><div class="v mono">{{if .View.RepoPath}}{{.View.RepoPath}}{{else}}—{{end}}</div></div>
  <div class="field"><div class="k">Hostname</div><div class="v">{{if .View.Hostname}}{{.View.Hostname}}{{else}}—{{end}}</div></div>
  <div class="field"><div class="k">Sentinel version</div><div class="v">{{if .View.SentinelVersion}}{{.View.SentinelVersion}}{{else}}—{{end}}</div></div>
</div>

<h2>Lifecycle</h2>
<div class="grid">
  <div class="field"><div class="k">Started</div><div class="v">{{.View.StartedAt}}</div></div>
  <div class="field"><div class="k">Stopped</div><div class="v">{{if .View.StoppedAt}}{{.View.StoppedAt}}{{else}}no clean stop reported{{end}}</div></div>
  <div class="field"><div class="k">Last seen by Fleet</div><div class="v">{{.View.LastSeenAt}}</div></div>
</div>

<h2>Policy enforced by this session</h2>
<div class="grid">
  <div class="field"><div class="k">Policy</div><div class="v">{{if .View.PolicyID}}{{.View.PolicyID}}{{if .View.PolicyVersion}} v{{.View.PolicyVersion}}{{end}}{{else}}—{{end}}</div></div>
  <div class="field"><div class="k">Policy hash</div><div class="v mono">{{if .View.PolicyHash}}{{.View.PolicyHash}}{{else}}—{{end}}</div></div>
  <div class="field"><div class="k">Signature</div><div class="v">{{if .View.SignatureState}}{{.View.SignatureState}}{{else}}—{{end}}</div></div>
  <div class="field"><div class="k">Signer</div><div class="v mono">{{if .View.SignerKeyID}}{{.View.SignerKeyID}}{{else}}—{{end}}</div></div>
</div>
<div class="note">This is what the session actually reported enforcing while it ran. It is a historical record and does not change when the Sentinel is later assigned a different policy.</div>

<h2>Governance activity (this session only)</h2>
<div class="grid">
  <div class="field"><div class="k">Allowed</div><div class="v">{{.View.AllowCount}}</div></div>
  <div class="field"><div class="k">Denied</div><div class="v">{{.View.DenyCount}}</div></div>
  <div class="field"><div class="k">Reverted</div><div class="v">{{.View.RevertedCount}}</div></div>
  <div class="field"><div class="k">Revert failed</div><div class="v">{{.View.RevertFailedCount}}</div></div>
  <div class="field"><div class="k">Last event</div><div class="v">{{if .View.LastEventAt}}{{.View.LastEventAt}}{{else}}—{{end}}</div></div>
</div>

<h2>Evidence</h2>
<div class="grid">
  <div class="field"><div class="k">Location</div><div class="v">{{.View.Evidence.Location}} TO SENTINEL</div></div>
  <div class="field"><div class="k">Kind</div><div class="v">{{.View.Evidence.Kind}}</div></div>
  <div class="field"><div class="k">Lookup key</div><div class="v mono">{{.View.Evidence.SessionID}}</div></div>
</div>
<div class="note"><strong>Raw evidence for this session never left the machine that produced it.</strong>
Fleet holds the metadata on this page and nothing else &mdash; no file contents, diffs, patches, or event logs.
The authoritative record lives on that machine and is inspectable there with
<code class="mono">airlock inspect {{.View.SessionID}}</code>, <code class="mono">airlock replay {{.View.SessionID}}</code>, and <code class="mono">airlock verify {{.View.SessionID}}</code>.
There is intentionally no button here to open it: this control plane has no access to that filesystem.</div>

<h2>Correlated governance alerts</h2>
{{if .Alerts}}
<table><tr><th>When</th><th>Event</th><th>Path</th><th>Detail</th></tr>
{{range .Alerts}}<tr><td>{{.At}}</td><td>{{.Type}}</td><td class="mono">{{if .Path}}{{.Path}}{{else}}—{{end}}</td><td>{{.Summary}}</td></tr>{{end}}
</table>
{{else}}<div class="empty">No alerts were reported for this session.</div>{{end}}
</body></html>`))

func (s *Server) handleSessionPage(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/fleet/sessions/"), "/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	view, alerts, ok := s.sessionDetail(id)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = sessionPage.Execute(w, struct {
		View   SessionView
		Alerts []Report
	}{View: view, Alerts: alerts})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = indexPage.Execute(w, nil)
}

func (s *Server) handleDetailPage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/fleet/sentinels/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	rec, ok := s.store.Get(id)
	if !ok {
		http.Error(w, "sentinel not found", http.StatusNotFound)
		return
	}
	view := s.viewOf(rec, time.Now().UTC())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = detailPage.Execute(w, view)
}

// shortID truncates a UUID for display without losing enough entropy to make
// two Sentinels or sessions on one page ambiguous.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// FormatAge renders how long ago t was, or "never" for a zero time. Used by
// `airlock fleet list`/`status` so the CLI table matches the web UI's
// freshness wording.
func FormatAge(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String() + " ago"
	case d < time.Hour:
		return d.Round(time.Minute).String() + " ago"
	default:
		return d.Round(time.Hour).String() + " ago"
	}
}

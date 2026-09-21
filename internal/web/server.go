package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/EliaxLab/SentinelAirlock/internal/events"
	"github.com/EliaxLab/SentinelAirlock/internal/index"
	"github.com/EliaxLab/SentinelAirlock/internal/review"
	"github.com/EliaxLab/SentinelAirlock/internal/rollback"
	"github.com/EliaxLab/SentinelAirlock/internal/runmeta"
)

type Server struct {
	readOnly       bool
	shutdownFunc   func() // called by the Stop Viewer UI action; nil-safe
	repoPath       string
	sentinelStatus SentinelStatusFunc
	sentinelStop   SentinelStopFunc
}

// ServerOptions carries the viewer's resolved repository context and trusted
// lifecycle operations. Sentinel controls are callbacks supplied by the CLI so
// the browser can never select a repository or PID to inspect/stop.
type ServerOptions struct {
	ReadOnly       bool
	ShutdownFunc   func()
	RepoPath       string
	SentinelStatus SentinelStatusFunc
	SentinelStop   SentinelStopFunc
}

type runCard struct {
	RunID         string
	Title         string
	Subtitle      string
	Command       string
	Outcome       string
	OutcomeClass  string
	Adapter       string
	When          string
	RiskSummary   string
	FilesChanged  int
	Blocked       int
	ReviewState   string
	VerifyState   string
	Signed        bool
	HasRollback   bool
	Target        string
	Mode          string
	Sandbox       string
	PolicyPack    string
	DenyRuleCount int
	SentinelState string
	ReplayURL     string
	RunURL        string
	ExportCmd     string
	RollbackCmd   string
}

type policyView struct {
	Pack         string
	Network      string
	Sandbox      string
	EnvAllowlist []string
	DenyRules    []string
	AllowRules   []string
	HasDenyRules bool
}

type timelineStep struct {
	Index   int
	TS      string
	Label   string
	Status  string
	Path    string
	Summary string
	Diff    string
	Detail  string
}

func Start(listen string, openBrowser bool, readOnly bool) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	return StartOnListener(ln, openBrowser, readOnly, nil)
}

func StartOnListener(ln net.Listener, openBrowser bool, readOnly bool, shutdownFunc func()) error {
	repoPath, _ := filepath.Abs(".")
	return StartOnListenerWithOptions(ln, openBrowser, ServerOptions{
		ReadOnly: readOnly, ShutdownFunc: shutdownFunc, RepoPath: repoPath,
	})
}

// StartOnListenerWithOptions is the repository-aware viewer entry point. The
// original StartOnListener remains as a compatibility wrapper for callers that
// do not need Sentinel lifecycle controls.
func StartOnListenerWithOptions(ln net.Listener, openBrowser bool, opts ServerOptions) error {
	s := &Server{
		readOnly:       opts.ReadOnly,
		shutdownFunc:   opts.ShutdownFunc,
		repoPath:       opts.RepoPath,
		sentinelStatus: opts.SentinelStatus,
		sentinelStop:   opts.SentinelStop,
	}
	if s.repoPath == "" {
		s.repoPath, _ = filepath.Abs(".")
	}
	mux := http.NewServeMux()
	s.register(mux)
	url := "http://" + ln.Addr().String()
	if openBrowser {
		_ = open(url)
	}
	fmt.Printf("airlock viewer listening on %s\n", url)
	return http.Serve(ln, mux)
}

func (s *Server) register(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handleRunsPage)
	mux.HandleFunc("/runs/", s.handleRunPage)
	mux.HandleFunc("/compare", s.handleComparePage)
	mux.HandleFunc("/files/", s.handleFiles)
	mux.HandleFunc("/api/runs", s.handleAPIRuns)
	mux.HandleFunc("/api/runs/", s.handleAPIRunRoutes)
	mux.HandleFunc("/api/state", s.handleAPIState)
	mux.HandleFunc("/api/compare/", s.handleAPICompare)
	mux.HandleFunc("/api/viewer", s.handleAPIViewer)
	mux.HandleFunc("/api/viewer/stop", s.handleAPIViewerStop)
	mux.HandleFunc("/api/sentinel", s.handleAPISentinel)
	mux.HandleFunc("/api/sentinel/stop", s.handleAPISentinelStop)
}

func (s *Server) handleRunsPage(w http.ResponseWriter, r *http.Request) {
	store := loadIndex()
	summary := map[string]int{"total": len(store.Runs)}
	cards := make([]runCard, 0, len(store.Runs))

	reviewFilter := strings.TrimSpace(r.URL.Query().Get("review"))
	verifyFilter := strings.TrimSpace(r.URL.Query().Get("verify"))
	signedFilter := strings.TrimSpace(r.URL.Query().Get("signed"))
	targetFilter := strings.TrimSpace(r.URL.Query().Get("target"))

	for _, e := range store.Runs {
		a, err := runmeta.LoadArtifacts(e.RunID)
		if err != nil {
			continue
		}
		card := deriveRunCard(a)
		if card.Mode == "sentinel" {
			if s.sentinelRollbackBlocked(a.Manifest) {
				card.SentinelState = "active"
			} else {
				card.SentinelState = "stopped"
			}
		}

		if reviewFilter != "" && card.ReviewState != reviewFilter {
			continue
		}
		if verifyFilter != "" && card.VerifyState != verifyFilter {
			continue
		}
		if signedFilter == "signed" && !card.Signed {
			continue
		}
		if signedFilter == "unsigned" && card.Signed {
			continue
		}
		if targetFilter != "" && card.Target != targetFilter {
			continue
		}

		cards = append(cards, card)
	}

	for _, c := range cards {
		if c.ReviewState != "" && c.ReviewState != "unreviewed" {
			summary["reviewed"]++
		}
		if c.VerifyState == "verified-signed" || c.VerifyState == "verified-unsigned" {
			summary["verified"]++
		}
		if c.Signed {
			summary["signed"]++
		}
		if c.Target == "remote" {
			summary["remote"]++
		} else {
			summary["local"]++
		}
	}

	t := template.Must(template.New("runs").Funcs(template.FuncMap{
		"reviewClass": func(state string) string {
			switch state {
			case "approved":
				return "ok"
			case "rejected":
				return "bad"
			case "needs-attention":
				return "warn"
			default:
				return "muted"
			}
		},
		"verifyClass": func(state string) string {
			switch state {
			case "verified-signed", "verified-unsigned":
				return "ok"
			case "hash-mismatch", "signature-invalid":
				return "bad"
			default:
				return "warn"
			}
		},
	}).Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel Airlock Viewer</title>
<style>
body{font-family:ui-sans-serif,system-ui,-apple-system;margin:24px;background:#f8fafc;color:#111}
h1{margin:0 0 8px}.muted{color:#64748b;font-size:14px}
.row{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 16px}
.stat{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:8px 12px}
.filters{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:10px;margin-bottom:12px}
.cards{display:flex;flex-direction:column;gap:10px}
.card{background:#fff;border:1px solid #dbe4ee;border-radius:14px;padding:14px}
.title{font-size:20px;font-weight:700}
.subtitle{margin-top:4px;color:#475569}
.meta{margin-top:10px;font-size:13px;color:#475569}
.badge{display:inline-block;border-radius:999px;border:1px solid #d1d5db;padding:2px 8px;font-size:12px;margin-right:6px}
.ok{background:#ecfdf5;border-color:#86efac}.warn{background:#fffbeb;border-color:#facc15}.bad{background:#fef2f2;border-color:#fca5a5}.mutedb{background:#f3f4f6}
.actions{margin-top:10px;display:flex;gap:8px;flex-wrap:wrap}
.btn{background:#0f172a;color:#fff;padding:6px 10px;border-radius:8px;text-decoration:none;font-size:13px}
.secondary{background:#334155}
.small{font-size:12px;color:#64748b;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
input,select{padding:6px 8px;border:1px solid #cbd5e1;border-radius:8px;background:#fff}
button{padding:6px 10px;border:0;background:#0f172a;color:#fff;border-radius:8px;cursor:pointer}
.statusline{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:12px;color:#64748b;margin:6px 0 14px}
.statusline .dot{width:7px;height:7px;border-radius:50%;background:#22a06b;display:inline-block}
.statusline .sep{opacity:.4}
.update-banner{display:none;position:sticky;top:0;z-index:10;background:#ddf4ff;border:1px solid #54aeff;border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:14px;font-weight:600}
.update-banner.show{display:block}
.sentinel-shell{background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:16px;padding:18px;margin:12px 0 18px;box-shadow:0 10px 28px rgba(15,23,42,.12)}
.sentinel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap}.sentinel-kicker{font-size:11px;font-weight:800;letter-spacing:.13em;color:#94a3b8}.sentinel-title{font-size:22px;font-weight:750;margin-top:3px}.sentinel-status{display:inline-flex;align-items:center;gap:7px;border:1px solid #475569;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:800;letter-spacing:.04em}.sentinel-status.active{background:#052e2b;border-color:#0f766e;color:#99f6e4}.sentinel-status.stopped{background:#312e1e;border-color:#a16207;color:#fde68a}.sentinel-status.inactive{background:#1e293b;color:#cbd5e1}.sentinel-dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.sentinel-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:14px}.sentinel-field{min-width:0;background:rgba(255,255,255,.035);border:1px solid #293548;border-radius:10px;padding:10px}.sentinel-field .k{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8}.sentinel-field .v{font-size:13px;font-weight:650;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sentinel-semantics{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-top:12px;padding:10px 12px;border:1px solid #293548;border-radius:10px;background:#111c2e}.sentinel-flow{font-weight:750;color:#f8fafc}.sentinel-copy{font-size:12px;color:#94a3b8;text-align:right}.sentinel-policy{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.sentinel-policy span{border:1px solid #334155;border-radius:999px;padding:3px 8px;font-size:11px;color:#cbd5e1}.sentinel-warning,.sentinel-error{margin-top:10px;padding:9px 11px;border-radius:9px;font-size:12px}.sentinel-warning{background:#3a2c12;border:1px solid #854d0e;color:#fde68a}.sentinel-error{background:#3b1318;border:1px solid #991b1b;color:#fecaca}
.sentinel-bar{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-top:16px}.sentinel-bar h3{font-size:13px;letter-spacing:.05em;text-transform:uppercase;margin:0;color:#cbd5e1}.sentinel-controls,.sentinel-filters{display:flex;gap:6px;flex-wrap:wrap}.sentinel-shell button,.sentinel-shell a.sentinel-btn{border:1px solid #475569;background:#1e293b;color:#e2e8f0;border-radius:7px;padding:5px 9px;font-size:12px;text-decoration:none;cursor:pointer}.sentinel-shell button:hover,.sentinel-shell a.sentinel-btn:hover{background:#334155}.sentinel-shell button.danger{border-color:#b91c1c;color:#fecaca}.sentinel-shell button[disabled]{opacity:.55;cursor:not-allowed}.sentinel-filter.selected{background:#e2e8f0;color:#0f172a;border-color:#e2e8f0}
.sentinel-activity{margin-top:9px;border:1px solid #293548;border-radius:10px;overflow:hidden}.activity-row{display:grid;grid-template-columns:86px minmax(120px,1fr) 76px minmax(130px,auto);gap:10px;align-items:center;padding:9px 11px;border-top:1px solid #293548;font-size:12px}.activity-row:first-child{border-top:0}.activity-path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.activity-op{color:#94a3b8;font-size:11px}.activity-state{display:flex;gap:5px;justify-content:flex-end;flex-wrap:wrap}.activity-badge{border-radius:999px;padding:2px 7px;font-weight:800;font-size:10px;letter-spacing:.035em}.activity-badge.allow{background:#064e3b;color:#a7f3d0}.activity-badge.deny{background:#7f1d1d;color:#fecaca}.activity-badge.reverted{background:#1e3a5f;color:#bfdbfe}.activity-badge.failed{background:#7c2d12;color:#ffedd5}.sentinel-empty{padding:18px;color:#94a3b8;text-align:center;font-size:13px}.sentinel-command{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#020617;border:1px solid #334155;border-radius:8px;padding:9px 11px;margin-top:12px;color:#cbd5e1;overflow:auto}
@media(max-width:850px){.sentinel-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.activity-row{grid-template-columns:70px minmax(100px,1fr) 62px}.activity-state{grid-column:2/4;justify-content:flex-start}.sentinel-copy{text-align:left}}
@media(max-width:520px){body{margin:14px}.sentinel-grid{grid-template-columns:1fr}.sentinel-semantics{align-items:flex-start;flex-direction:column}.activity-row{grid-template-columns:64px minmax(0,1fr)}.activity-op{grid-column:2}.activity-state{grid-column:2}}
@media(prefers-color-scheme:dark){body{background:#07111f;color:#e5e7eb}.card,.filters,.stat{background:#101b2b;border-color:#28364a}.subtitle,.meta,.muted,.small,.statusline{color:#94a3b8}input,select{background:#0f172a;color:#e5e7eb;border-color:#475569}.viewer-panel{background:#101b2b;color:#e5e7eb}}
</style></head><body data-fingerprint="{{.Fingerprint}}" data-readonly="{{if .ReadOnly}}1{{else}}0{{end}}">
<div class="update-banner" id="update-banner">Runs updated. Refreshing…</div>
<h1>Sentinel Airlock Runs</h1>
<div class="muted">Agent autopilot with DVR controls: see what happened, what changed, what was blocked, and what to do next.</div>
<div class="statusline">
  <span id="viewer-chip-wrap" style="position:relative">
    <button id="viewer-chip" onclick="toggleViewerPanel()" title="Airlock viewer status"
            style="background:none;border:1px solid #d1d5db;border-radius:999px;padding:2px 8px 2px 6px;font-size:12px;cursor:pointer;color:#64748b;display:inline-flex;align-items:center;gap:5px;line-height:1">
      <span style="width:6px;height:6px;border-radius:50%;background:#22a06b;display:inline-block;flex-shrink:0"></span>
      {{if .ReadOnly}}read-only viewer{{else}}local operator mode{{end}}
      <span style="font-size:10px;opacity:.6">&#9660;</span>
    </button>
    <div id="viewer-panel" style="display:none;position:absolute;top:calc(100% + 6px);left:0;z-index:200;background:#fff;border:1px solid #d1d5db;border-radius:12px;padding:14px;box-shadow:0 8px 24px rgba(0,0,0,.12);min-width:300px;color:#111;font-size:13px">
      <div style="font-weight:700;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center">
        Airlock Viewer
        <button onclick="toggleViewerPanel()" style="background:none;border:none;cursor:pointer;color:#64748b;font-size:16px;line-height:1;padding:0">&#215;</button>
      </div>
      <div id="viewer-panel-body">Loading&#8230;</div>
    </div>
  </span>
  <span class="sep">·</span><span>watching <span class="small">.airlock/index.json</span></span>
  <span class="sep">·</span><span>auto-refresh <span id="refresh-status">on</span></span>
  <span class="sep">·</span><span>last checked <span class="small" id="last-checked">—</span></span>
</div>

<section class="sentinel-shell" id="sentinel-panel" aria-live="polite" aria-label="Sentinel status">
  <div class="sentinel-empty">Checking Sentinel status&#8230;</div>
</section>

<div class="row">
  <div class="stat">total {{.Summary.total}}</div>
  <div class="stat">reviewed {{.Summary.reviewed}}</div>
  <div class="stat">verified {{.Summary.verified}}</div>
  <div class="stat">signed {{.Summary.signed}}</div>
  <div class="stat">local {{.Summary.local}}</div>
  <div class="stat">remote {{.Summary.remote}}</div>
</div>

<form class="filters" method="get" action="/">
  <label>review <select name="review"><option value="">all</option><option value="unreviewed">unreviewed</option><option value="approved">approved</option><option value="rejected">rejected</option><option value="needs-attention">needs-attention</option></select></label>
  <label>verify <select name="verify"><option value="">all</option><option value="verified-signed">verified-signed</option><option value="verified-unsigned">verified-unsigned</option><option value="hash-mismatch">hash-mismatch</option><option value="signature-invalid">signature-invalid</option></select></label>
  <label>signed <select name="signed"><option value="">all</option><option value="signed">signed</option><option value="unsigned">unsigned</option></select></label>
  <label>target <select name="target"><option value="">all</option><option value="local">local</option><option value="remote">remote</option></select></label>
  <button type="submit">Apply</button>
</form>

{{if not .Cards}}
<div class="card">No runs yet. Next step: <code>./airlock run --agent generic-shell --cmd 'mkdir -p src; echo hi > src/test.txt' --repo .</code></div>
{{end}}

<div class="cards">
{{range .Cards}}
<div class="card">
  <div class="title">{{.Title}}</div>
  <div class="subtitle">{{.Subtitle}}</div>
  <div style="margin-top:8px">
    <span class="badge {{reviewClass .ReviewState}}">review {{.ReviewState}}</span>
    <span class="badge {{verifyClass .VerifyState}}">{{.VerifyState}}</span>
    <span class="badge {{if .Signed}}ok{{else}}mutedb{{end}}">{{if .Signed}}signed{{else}}unsigned{{end}}</span>
    <span class="badge mutedb">{{.Target}}</span>
    {{if .SentinelState}}<span class="badge {{if eq .SentinelState "active"}}ok{{else}}mutedb{{end}}">sentinel: {{.SentinelState}}</span>{{end}}
    {{if gt .DenyRuleCount 0}}<span class="badge mutedb">deny: {{.DenyRuleCount}}</span>{{else}}<span class="badge mutedb" style="opacity:.6">no path denies</span>{{end}}
    {{if .HasRollback}}<span class="badge warn">rolled back</span>{{end}}
  </div>
  <div class="meta">{{.When}} · adapter={{.Adapter}} · sandbox={{.Sandbox}} · pack={{.PolicyPack}}</div>
  {{if .Command}}<div class="small" style="margin-top:6px;word-break:break-all">{{.Command}}</div>{{end}}
  <div class="actions">
    <a class="btn" href="{{.RunURL}}">View run</a>
    <a class="btn secondary" href="{{.RunURL}}#timeline">Replay</a>
    <a class="btn secondary" href="{{.RunURL}}#patch">Patch</a>
    <a class="btn secondary" href="{{.RunURL}}#export">Export</a>
  </div>
  <div class="small">run_id {{.RunID}}</div>
</div>
{{end}}
</div>
<script>
(function(){
  var base=document.body.dataset.fingerprint;
  var statusEl=document.getElementById("refresh-status");
  var checkedEl=document.getElementById("last-checked");
  var banner=document.getElementById("update-banner");
  var failures=0;
  function pad(n){return n<10?"0"+n:""+n;}
  function now(){var d=new Date();return pad(d.getHours())+":"+pad(d.getMinutes())+":"+pad(d.getSeconds());}
  function poll(){
    fetch("/api/state",{cache:"no-store"})
      .then(function(r){return r.ok?r.json():Promise.reject(r.status);})
      .then(function(s){
        failures=0;
        if(checkedEl)checkedEl.textContent=now();
        if(s&&s.fingerprint&&s.fingerprint!==base){
          if(banner)banner.classList.add("show");
          if(statusEl)statusEl.textContent="updating…";
          setTimeout(function(){location.reload();},700);
        }
      })
      .catch(function(){failures++;if(failures>=3&&statusEl)statusEl.textContent="paused (viewer offline)";});
  }
  poll();
  setInterval(poll,3000);
})();
function toggleViewerPanel(){
  var panel=document.getElementById("viewer-panel");
  if(!panel)return;
  if(panel.style.display!=="none"){panel.style.display="none";return;}
  panel.style.display="block";
  loadViewerPanel();
}
function loadViewerPanel(){
  var body=document.getElementById("viewer-panel-body");
  if(!body)return;
  body.innerHTML="Loading&#8230;";
  fetch("/api/viewer",{cache:"no-store"})
    .then(function(r){return r.ok?r.json():Promise.reject(r.status);})
    .then(function(d){renderViewerPanel(d,body);})
    .catch(function(){body.innerHTML="<span style='color:#ef4444'>Could not reach viewer API.</span>";});
}
function renderViewerPanel(d,body){
  var ro=document.body.dataset.readonly==="1";
  if(!d.running){body.innerHTML="<div style='color:#64748b;text-align:center;padding:8px 0'>No viewer running.</div>";return;}
  var rows="";
  rows+="<div style='display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>mode</span><span style='font-weight:600'>"+(d.mode||"&#8212;")+"</span></div>";
  rows+="<div style='display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>URL</span><span><a href='"+(d.url||"#")+"' style='color:#0284c7'>"+(d.url||"&#8212;")+"</a></span></div>";
  rows+="<div style='display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>uptime</span><span>"+(d.uptime||"&#8212;")+"</span></div>";
  rows+="<div style='display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>PID</span><span>"+(d.pid||"&#8212;")+"</span></div>";
  if(d.log){rows+="<div style='padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>log&nbsp;</span><span style='font-size:11px;word-break:break-all;color:#64748b'>"+d.log+"</span></div>";}
  var btns="<div style='margin-top:12px;display:flex;gap:8px;flex-wrap:wrap'>";
  btns+="<button onclick='loadViewerPanel()' style='font-size:12px;background:#334155;border:none;color:#fff;padding:4px 10px;border-radius:6px;cursor:pointer'>Refresh</button>";
  if(!ro){btns+="<button onclick='stopViewer()' style='font-size:12px;background:#dc2626;border:none;color:#fff;padding:4px 10px;border-radius:6px;cursor:pointer'>Stop Viewer</button>";}
  btns+="</div>";
  body.innerHTML=rows+btns;
}
function stopViewer(){
  if(!confirm("Stop the Airlock viewer?\n\nThis will shut down the local HTTP server. You can restart it with:\n\n  airlock serve --background --open"))return;
  var body=document.getElementById("viewer-panel-body");
  if(body)body.innerHTML="Stopping&#8230;";
  fetch("/api/viewer/stop",{method:"POST",cache:"no-store"})
    .then(function(r){return r.ok?r.text():Promise.reject(r.status);})
    .then(function(html){document.open();document.write(html);document.close();})
    .catch(function(e){if(body)body.innerHTML="<span style='color:#ef4444'>Stop failed ("+e+"). Try: airlock serve --stop</span>";});
}
document.addEventListener("click",function(e){
  var wrap=document.getElementById("viewer-chip-wrap");
  var panel=document.getElementById("viewer-panel");
  if(wrap&&panel&&!wrap.contains(e.target)&&panel.style.display!=="none"){panel.style.display="none";}
});
var sentinelFilter="all";
function sentinelEsc(v){return String(v==null?"":v).replace(/[&<>"']/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c];});}
function sentinelTime(v){if(!v)return "—";var d=new Date(v);return isNaN(d.getTime())?v:d.toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});}
function setSentinelFilter(v){sentinelFilter=v;loadSentinel();}
function sentinelActivityHTML(items,active){
  var shown=(items||[]).filter(function(a){
    if(sentinelFilter==="allowed")return a.decision==="allow";
    if(sentinelFilter==="denied")return a.decision==="deny";
    if(sentinelFilter==="reverted")return a.revert_state==="reverted";
    if(sentinelFilter==="failed")return a.revert_state==="failed";
    return true;
  });
  if(!shown.length)return "<div class='sentinel-empty'>"+((items||[]).length?"No activity matches this filter.":(active?"Sentinel is active. Waiting for filesystem activity.":"No filesystem activity was recorded for this session."))+"</div>";
  return shown.map(function(a){
    var badges="<span class='activity-badge "+(a.decision==="deny"?"deny":"allow")+"'>"+sentinelEsc((a.decision||"allow").toUpperCase())+"</span>";
    if(a.revert_state==="reverted")badges+="<span class='activity-badge reverted'>REVERTED</span>";
    if(a.revert_state==="failed")badges+="<span class='activity-badge failed' title='"+sentinelEsc(a.revert_error||"Revert failed")+"'>REVERT FAILED</span>";
    return "<div class='activity-row'><span>"+sentinelTime(a.timestamp)+"</span><span class='activity-path' title='"+sentinelEsc(a.path)+"'>"+sentinelEsc(a.path)+"</span><span class='activity-op'>"+sentinelEsc(a.operation||"WRITE")+"</span><span class='activity-state'>"+badges+"</span></div>";
  }).join("");
}
function renderSentinel(d){
  var panel=document.getElementById("sentinel-panel");if(!panel)return;
  var state=d.state||"inactive", active=!!d.running;
  var h="<div class='sentinel-head'><div><div class='sentinel-kicker'>SENTINEL</div><div class='sentinel-title'>Repository governance</div></div><span class='sentinel-status "+sentinelEsc(state)+"'><span class='sentinel-dot'></span>"+sentinelEsc(state.toUpperCase())+"</span></div>";
  h+="<div class='sentinel-grid'><div class='sentinel-field'><div class='k'>Repository</div><div class='v' title='"+sentinelEsc(d.repo)+"'>"+sentinelEsc(d.repo||"—")+"</div></div><div class='sentinel-field'><div class='k'>Session</div><div class='v' title='"+sentinelEsc(d.session_id)+"'>"+sentinelEsc(d.session_id||"—")+"</div></div><div class='sentinel-field'><div class='k'>PID / uptime</div><div class='v'>"+(active?sentinelEsc(d.pid)+" · "+sentinelEsc(d.uptime||"—"):"—")+"</div></div><div class='sentinel-field'><div class='k'>Started</div><div class='v' title='"+sentinelEsc(d.started_at)+"'>"+sentinelEsc(d.started_at||"—")+"</div></div></div>";
  h+="<div class='sentinel-semantics'><span class='sentinel-flow'>"+sentinelEsc(d.enforcement)+"</span><span class='sentinel-copy'>"+sentinelEsc(d.semantics)+"</span></div>";
  if(d.session_id){h+="<div class='sentinel-policy'><span>Policy pack: "+sentinelEsc(d.policy&&d.policy.pack||"project")+"</span><span>Allow rules: "+sentinelEsc(d.policy&&d.policy.allow_rules||0)+"</span><span>Deny rules: "+sentinelEsc(d.policy&&d.policy.deny_rules||0)+"</span><span>Status: "+sentinelEsc(d.status)+"</span></div>";}
  if(d.session_id&&d.policy&&d.policy.deny_rules===0)h+="<div class='sentinel-warning'>No explicit path deny rules are configured for this session.</div>";
  (d.errors||[]).forEach(function(e){h+="<div class='sentinel-error'>"+sentinelEsc(e)+"</div>";});
  if(!d.session_id){h+="<div class='sentinel-command'>airlock sentinel --repo . --background</div>";panel.innerHTML=h;return;}
  h+="<div class='sentinel-bar'><h3>Recent Sentinel activity</h3><div class='sentinel-controls'><a class='sentinel-btn' href='/runs/"+encodeURIComponent(d.session_id)+"'>Open session</a><button type='button' onclick='loadSentinel()'>Refresh</button>";
  if(active&&!d.read_only)h+="<button class='danger' id='sentinel-stop' type='button' onclick='stopSentinel()'>Stop Sentinel</button>";
  h+="</div></div><div class='sentinel-bar'><div class='sentinel-filters'>";
  [["all","All"],["allowed","Allowed"],["denied","Denied"],["reverted","Reverted"],["failed","Revert failed"]].forEach(function(f){h+="<button type='button' class='sentinel-filter "+(sentinelFilter===f[0]?"selected":"")+"' onclick=\"setSentinelFilter('"+f[0]+"')\">"+f[1]+"</button>";});
  h+="</div></div><div class='sentinel-activity'>"+sentinelActivityHTML(d.recent_activity,active)+"</div>";
  if(!active)h+="<div class='sentinel-command'>airlock sentinel --repo . --background</div>";
  panel.innerHTML=h;
}
function loadSentinel(){
  fetch("/api/sentinel",{cache:"no-store"}).then(function(r){return r.ok?r.json():Promise.reject(r.status);}).then(renderSentinel).catch(function(){var p=document.getElementById("sentinel-panel");if(p)p.innerHTML="<div class='sentinel-error'>Sentinel status could not be refreshed. The viewer will retry automatically.</div>";});
}
function stopSentinel(){
  if(!confirm("Stop Sentinel for this repository?\n\nPending filesystem evaluations will drain and final evidence will be flushed."))return;
  var b=document.getElementById("sentinel-stop");if(b){b.disabled=true;b.textContent="Stopping…";}
  fetch("/api/sentinel/stop",{method:"POST",cache:"no-store"}).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(t);});return r.json();}).then(function(){loadSentinel();}).catch(function(e){alert("Sentinel stop failed. "+e.message);loadSentinel();});
}
loadSentinel();setInterval(loadSentinel,2000);
</script>
</body></html>`))

	_, fingerprint := computeGlobalState()
	_ = t.Execute(w, map[string]any{"Cards": cards, "Summary": summary, "Fingerprint": fingerprint, "ReadOnly": s.readOnly})
}

// reviewView holds review fields as plain strings so Go templates can pass them
// to string-typed template functions without a named-type mismatch.
// review.State is `type State string`; html/template does not auto-convert it.
type reviewView struct {
	State     string
	Note      string
	Reviewer  string
	Timestamp string
}

func (s *Server) handleRunPage(w http.ResponseWriter, r *http.Request) {
	runID := strings.TrimPrefix(r.URL.Path, "/runs/")
	a, err := runmeta.LoadArtifacts(runID)
	if err != nil {
		http.Error(w, "Run not found: "+runID+"\n\nThis run may have been cleaned up or the ID is invalid.", http.StatusNotFound)
		return
	}
	rev, _ := review.Load(a.RunDir)
	vr, _ := runmeta.VerifyRun(runID, a.Manifest)

	// Convert review.Record to plain strings. review.State is a named string type;
	// passing it directly to reviewClass(string) causes a silent template type-mismatch
	// that truncates the page at the Governance Outcome card.
	rv := reviewView{
		State:     string(rev.State),
		Note:      rev.Note,
		Reviewer:  rev.Reviewer,
		Timestamp: rev.Timestamp,
	}
	if rv.State == "" {
		rv.State = "unreviewed"
	}

	card := deriveRunCard(a)
	steps := deriveTimelineSteps(a.Events)
	patchSummary := derivePatchSummary(a.Events)

	// Load rollback.json if present
	type rollbackRec struct {
		Mode       string   `json:"mode"`
		Checkpoint string   `json:"checkpoint"`
		Paths      []string `json:"paths"`
		Timestamp  string   `json:"timestamp"`
		Status     string   `json:"status"`
	}
	var rollbackData *rollbackRec
	if b, readErr := os.ReadFile(filepath.Join(a.RunDir, "rollback.json")); readErr == nil {
		var rr rollbackRec
		if json.Unmarshal(b, &rr) == nil {
			rollbackData = &rr
		}
	}

	// Derive denied items from events
	type deniedItem struct {
		Path        string
		Reason      string
		Risk        string
		Explanation string
		RevertState string
		RevertError string
	}
	var deniedItems []deniedItem
	for _, e := range a.Events {
		if e.Type != "POLICY_DENY" {
			continue
		}
		di := deniedItem{Path: e.Path}
		if reason, ok := e.Meta["reason"].(string); ok {
			di.Reason = reason
		} else {
			di.Reason = e.Summary
		}
		if lvl, ok := e.Risk["level"].(string); ok {
			di.Risk = lvl
		}
		if reverted, ok := e.Meta["reverted"].(bool); ok {
			if reverted {
				di.RevertState = "reverted"
			} else {
				di.RevertState = "failed"
			}
		}
		if revertErr, ok := e.Meta["revert_error"].(string); ok && revertErr != "" {
			di.RevertState = "failed"
			di.RevertError = revertErr
		}
		di.Explanation = webDenyExplanation(di.Reason)
		deniedItems = append(deniedItems, di)
	}

	// Build governance sentence
	sentence := webGovernanceSentence(a.Manifest, a.Events, rollbackData != nil, vr.Status)

	// Replay playback: high-level summary + grouped events (ENV_DENY collapsed).
	replaySum, replayGroups := buildReplay(a.Events)

	// Next-step guidance from observable state.
	hasCheckpoint := len(a.Manifest.Checkpoints) > 0
	isSentinel := a.Manifest.ExecutionMode == "sentinel"
	inPlace := a.Manifest.Sandbox.Mode == "off"
	activeSentinel := s.sentinelRollbackBlocked(a.Manifest)
	ns := computeNextStep(runID, rv.State, vr.Status, rollbackData != nil, len(deniedItems) > 0, hasCheckpoint, s.readOnly)
	if activeSentinel {
		ns = nextStep{
			Headline: "Sentinel is actively monitoring this repository",
			Detail:   "Evidence updates as filesystem activity arrives. Stop Sentinel before using rollback.",
			Command:  "airlock replay " + runID + " --tail 100",
			Class:    "ok",
		}
	} else if inPlace {
		ns.Detail = strings.ReplaceAll(ns.Detail, "the isolated Airlock workspace", "this in-place session")
		ns.Detail = strings.ReplaceAll(ns.Detail, "the Airlock workspace", "the real repository's touched paths")
	}

	// Rollback flash (from the POST redirect) and the unmistakable top-level
	// rollback state: unavailable | available | complete | failed.
	rollbackFlash := r.URL.Query().Get("rollback") // "success" | "error" | ""
	rollbackReason := r.URL.Query().Get("reason")
	rollbackState := "unavailable"
	switch {
	case rollbackData != nil:
		rollbackState = "complete"
	case rollbackFlash == "error":
		rollbackState = "failed"
	case hasCheckpoint:
		rollbackState = "available"
	}
	if activeSentinel && rollbackData == nil {
		rollbackState = "unavailable"
	}

	// Live state fingerprint for auto-refresh polling.
	liveState := computeRunState(a)

	t := template.Must(template.New("run").Funcs(template.FuncMap{
		"reviewClass": func(state string) string {
			switch state {
			case "approved":
				return "ok"
			case "rejected":
				return "bad"
			case "needs-attention":
				return "warn"
			default:
				return "mutedb"
			}
		},
		"verifyClass": func(state string) string {
			switch state {
			case "verified-signed", "verified-unsigned":
				return "ok"
			case "hash-mismatch", "signature-invalid":
				return "bad"
			default:
				return "warn"
			}
		},
		"riskClass": func(level string) string {
			switch strings.ToLower(level) {
			case "high":
				return "bad"
			case "medium":
				return "warn"
			case "low":
				return "ok"
			}
			return "mutedb"
		},
		"stepClass": func(status string) string {
			switch status {
			case "blocked":
				return "step-blocked"
			case "changed":
				return "step-changed"
			case "rollback":
				return "step-rollback"
			case "info":
				return "step-info"
			default:
				return ""
			}
		},
		"nsClass": func(class string) string {
			switch class {
			case "ok":
				return "ok"
			case "warn":
				return "warn"
			case "bad":
				return "bad"
			default:
				return "mutedb"
			}
		},
	}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Run {{.RunID}} · Sentinel Airlock</title>
<style>
:root{--bg:#f6f8fa;--panel:#fff;--border:#d0d7de;--text:#1f2328;--muted:#656d76;--accent:#0969da;
  --ok-bg:#dafbe1;--ok-bd:#2da44e;--ok-fg:#1a7f37;
  --warn-bg:#fff8c5;--warn-bd:#d4a72c;--warn-fg:#7d4e00;
  --bad-bg:#ffebe9;--bad-bd:#cf222e;--bad-fg:#a40e26;
  --muted-bg:#eaeef2;--muted-bd:#afb8c1;--muted-fg:#57606a;
  --outcome-bg:#ddf4ff;--outcome-bd:#54aeff;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){
  :root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
    --ok-bg:#12261a;--ok-bd:#2ea043;--ok-fg:#7ee2a8;
    --warn-bg:#2b2410;--warn-bd:#d29922;--warn-fg:#e3b341;
    --bad-bg:#2b1416;--bad-bd:#f85149;--bad-fg:#ff9492;
    --muted-bg:#21262d;--muted-bd:#484f58;--muted-fg:#adbac7;
    --outcome-bg:#0d1f38;--outcome-bd:#1f6feb}}
*{box-sizing:border-box}
body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);margin:0;line-height:1.5;font-size:15px}
.wrap{max-width:980px;margin:0 auto;padding:24px 20px 60px}
.topbar{display:flex;align-items:center;gap:10px;margin-bottom:18px;flex-wrap:wrap}
.topbar a{color:var(--muted);font-size:13px;text-decoration:none}
.topbar a:hover{text-decoration:underline}
h1{font-size:22px;margin:0 0 4px;font-weight:700}
h2{font-size:12px;margin:0 0 12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:700}
.governance-sentence{font-size:15px;color:var(--muted);margin:0 0 16px;line-height:1.6}
.section{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin:12px 0}
.section.outcome{border-color:var(--outcome-bd);background:var(--outcome-bg)}
.section.alert-section{border-color:var(--bad-bd);background:var(--bad-bg)}
.section.rollback-section{border-color:var(--warn-bd);background:var(--warn-bg)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.field .k{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.field .v{font-weight:600}
.mono{font-family:var(--mono);font-size:13px}
.muted{color:var(--muted)}
.badge{display:inline-block;border-radius:999px;border:1px solid var(--muted-bd);padding:2px 9px;font-size:12px;font-weight:600;background:var(--muted-bg);color:var(--muted-fg);text-decoration:none}
.ok{background:var(--ok-bg);border-color:var(--ok-bd);color:var(--ok-fg)}
.warn{background:var(--warn-bg);border-color:var(--warn-bd);color:var(--warn-fg)}
.bad{background:var(--bad-bg);border-color:var(--bad-bd);color:var(--bad-fg)}
.mutedb{background:var(--muted-bg);border-color:var(--muted-bd);color:var(--muted-fg)}
.badges{display:flex;flex-wrap:wrap;gap:7px;margin:6px 0}
.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.btn{background:#0f172a;color:#fff;padding:7px 12px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;border:0;cursor:pointer;display:inline-block}
.btn.primary{background:var(--accent);color:#fff}
.btn.secondary{background:var(--muted-bg);color:var(--text);border:1px solid var(--border)}
.btn.disabled{opacity:.45;cursor:default;pointer-events:none}
.btn-label{font-size:11px;color:var(--muted);margin-left:4px}
.step{border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin:7px 0;background:var(--panel)}
.step.step-blocked{border-color:var(--bad-bd);background:var(--bad-bg)}
.step.step-changed{background:var(--muted-bg)}
.step.step-rollback{border-color:var(--warn-bd);background:var(--warn-bg)}
.step.step-info{border-color:var(--muted-bd);background:var(--muted-bg)}
.stephead{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
.steplabel{font-weight:600;font-size:13px}
.steptime{color:var(--muted);font-size:12px;font-family:var(--mono)}
.steppath{font-family:var(--mono);font-size:12px;margin-top:3px;color:var(--accent)}
.stepdetail{font-size:12px;color:var(--muted);margin-top:3px}
.stepreason{font-size:12px;color:var(--muted);font-style:italic;margin-top:3px}
.stepsummary{font-size:13px;color:var(--muted);margin-top:4px}
pre{white-space:pre-wrap;background:#0b1220;color:#e5e7eb;padding:12px;border-radius:10px;overflow:auto;font-size:12.5px;font-family:var(--mono)}
@media(prefers-color-scheme:light){pre{background:#1f2328;color:#e6edf3}}
details{margin-top:6px}
summary{cursor:pointer;color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
tr.deny-row td{background:var(--bad-bg)}
.deny-explanation{font-size:12px;color:var(--muted);font-style:italic;margin-top:3px}
input,select{padding:6px 8px;border:1px solid var(--border);border-radius:7px;background:var(--panel);color:var(--text);font-size:13px}
.caveat{font-size:12px;color:var(--muted);border-left:3px solid var(--warn-bd);padding-left:10px;margin-top:10px;line-height:1.6}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.small{font-size:12px;color:var(--muted)}
.hint{font-size:12px;font-family:var(--mono);color:var(--muted);margin-top:4px}
.statusline{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-bottom:14px}
.statusline .dot{width:7px;height:7px;border-radius:50%;background:var(--ok-bd);display:inline-block}
.statusline .sep{opacity:.4}
.update-banner{display:none;position:sticky;top:0;z-index:10;background:var(--outcome-bg);border:1px solid var(--outcome-bd);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:14px;font-weight:600;color:var(--text)}
.update-banner.show{display:block}
.section.next-step{border-width:1px}
.section.next-step.ok{border-color:var(--ok-bd);background:var(--ok-bg)}
.section.next-step.warn{border-color:var(--warn-bd);background:var(--warn-bg)}
.section.next-step.bad{border-color:var(--bad-bd);background:var(--bad-bg)}
.section.next-step.mutedb{border-color:var(--muted-bd);background:var(--muted-bg)}
.ns-headline{font-size:16px;font-weight:700;margin:0 0 4px}
.ns-detail{font-size:14px;margin:0 0 8px;line-height:1.55}
.replay-counts{display:flex;flex-wrap:wrap;gap:8px;margin:4px 0 14px}
.replay-chip{border:1px solid var(--border);border-radius:8px;padding:6px 10px;font-size:12px;background:var(--panel);min-width:88px}
.replay-chip .n{font-size:18px;font-weight:700;display:block}
.replay-chip .l{color:var(--muted);text-transform:uppercase;letter-spacing:.03em;font-size:10px}
.replay-group{margin:14px 0}
.replay-group>.gname{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:6px}
.envnote{border:1px solid var(--muted-bd);background:var(--muted-bg);border-radius:8px;padding:10px 12px;margin:8px 0;font-size:13px}
.flash{border-radius:10px;padding:12px 16px;margin-bottom:14px;font-size:14px;font-weight:600;display:flex;align-items:center;gap:8px}
.flash.success{border:1px solid var(--ok-bd);background:var(--ok-bg);color:var(--text)}
.flash.error{border:1px solid var(--bad-bd);background:var(--bad-bg);color:var(--text)}
.flash .reason{font-weight:400;font-family:var(--mono);font-size:12px;opacity:.85}
.rollback-hero{border:2px solid var(--ok-bd);background:var(--ok-bg);border-radius:12px;padding:16px 18px;margin-bottom:16px}
.rollback-hero h2{margin:0 0 8px;font-size:18px}
.rollback-hero ul{margin:0;padding-left:20px;font-size:14px;line-height:1.7}
.rollback-hero .chk{color:var(--ok-bd);font-weight:700}
.rb-badge.available{border-color:var(--warn-bd);background:var(--warn-bg)}
.rb-badge.complete{border-color:var(--ok-bd);background:var(--ok-bg)}
.rb-badge.failed{border-color:var(--bad-bd);background:var(--bad-bg)}
.rb-badge.unavailable{border-color:var(--muted-bd);background:var(--muted-bg)}
</style></head><body data-run-id="{{.RunID}}" data-fingerprint="{{.Fingerprint}}" data-readonly="{{if .ReadOnly}}1{{else}}0{{end}}">
<div class="wrap">

<div class="update-banner" id="update-banner">Evidence updated. Refreshing…</div>

{{if eq .RollbackFlash "success"}}<div class="flash success">✓ Rollback complete — workspace restored from cp-0.</div>{{end}}
{{if eq .RollbackFlash "error"}}<div class="flash error">✗ Rollback failed.{{if .RollbackReason}} <span class="reason">{{.RollbackReason}}</span>{{else}} See the viewer log (.airlock/viewer.log) for details.{{end}}</div>{{end}}

<div class="topbar">
  <a href="/">← All runs</a>
  <span class="muted">/</span>
  <span class="mono small">{{.RunID}}</span>
  {{if .ReadOnly}}<span class="badge mutedb">read-only viewer</span>{{else}}<span class="badge ok">operator viewer</span>{{end}}
</div>

<div class="statusline">
  <span id="viewer-chip-wrap" style="position:relative">
    <button id="viewer-chip" onclick="toggleViewerPanel()" title="Airlock viewer status"
            style="background:none;border:1px solid #d1d5db;border-radius:999px;padding:2px 8px 2px 6px;font-size:12px;cursor:pointer;color:#64748b;display:inline-flex;align-items:center;gap:5px;line-height:1">
      <span style="width:6px;height:6px;border-radius:50%;background:#22a06b;display:inline-block;flex-shrink:0"></span>
      {{if .ReadOnly}}read-only viewer{{else}}local operator mode{{end}}
      <span style="font-size:10px;opacity:.6">&#9660;</span>
    </button>
    <div id="viewer-panel" style="display:none;position:absolute;top:calc(100% + 6px);left:0;z-index:200;background:#fff;border:1px solid #d1d5db;border-radius:12px;padding:14px;box-shadow:0 8px 24px rgba(0,0,0,.12);min-width:300px;color:#111;font-size:13px">
      <div style="font-weight:700;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center">
        Airlock Viewer
        <button onclick="toggleViewerPanel()" style="background:none;border:none;cursor:pointer;color:#64748b;font-size:16px;line-height:1;padding:0">&#215;</button>
      </div>
      <div id="viewer-panel-body">Loading&#8230;</div>
    </div>
  </span>
  <span class="sep">·</span><span>watching <span class="mono">.airlock/index.json</span></span>
  <span class="sep">·</span><span>auto-refresh <span id="refresh-status">on</span></span>
  <span class="sep">·</span><span>last evidence update <span class="mono" id="evidence-updated">{{if .Updated}}{{.Updated}}{{else}}—{{end}}</span></span>
  <span class="sep">·</span><span>last checked <span class="mono" id="last-checked">—</span></span>
</div>

<h1>{{.Card.Title}}</h1>
<div class="governance-sentence">{{.GovernanceSentence}}</div>

<!-- ── Prominent rollback state (top of page, unmistakable) ── -->
{{if .Rollback}}
<div class="rollback-hero">
  <h2>↩ Workspace rolled back</h2>
  <ul>
    <li><span class="chk">✓</span> Restored from checkpoint {{.Rollback.Checkpoint}}</li>
    <li><span class="chk">✓</span> Review reset to <strong>needs-attention</strong></li>
    <li><span class="chk">✓</span> Original repo untouched</li>
    <li><span class="chk">✓</span> Digest rebuilt · verification: {{.Verify.Status}}</li>
  </ul>
</div>
{{end}}

<!-- ── Governance outcome (executive summary) ── -->
<div class="section outcome">
  <h2>Governance outcome</h2>
  <div class="badges">
    <span class="badge {{reviewClass .Review.State}}">review: {{.Review.State}}</span>
    <span class="badge {{verifyClass .Verify.Status}}">{{.Verify.Status}}</span>
    <span class="badge {{if .Manifest.Digest.Signed}}ok{{else}}mutedb{{end}}">{{if .Manifest.Digest.Signed}}signed{{else}}unsigned{{end}}</span>
    <span class="badge {{if gt .Card.FilesChanged 0}}ok{{else}}mutedb{{end}}">{{.Card.FilesChanged}} file(s) changed</span>
    {{if gt .Card.Blocked 0}}<span class="badge bad">{{.Card.Blocked}} blocked</span>{{end}}
    <span class="badge rb-badge {{.RollbackState}}">rollback: {{.RollbackState}}</span>
    {{if .Rollback}}<span class="badge warn">rolled back ({{.Rollback.Mode}})</span>{{else if eq .RollbackState "available"}}<span class="badge warn">rollback available</span>{{end}}
    <span class="badge mutedb">{{.Manifest.Adapter.Name}}</span>
    <span class="badge mutedb">sandbox: {{.Manifest.Sandbox.Mode}}</span>
    {{if .IsSentinel}}<span class="badge {{if .ActiveSentinel}}ok{{else}}mutedb{{end}}">sentinel: {{if .ActiveSentinel}}active{{else}}stopped{{end}}</span>{{end}}
  </div>
  <div style="margin-top:14px">
    <h2 style="margin-bottom:8px">Actions</h2>
    <div class="actions">
      <a class="btn primary" href="/files/{{.RunID}}/report/index.html" target="_blank">Open full report ↗</a>
      <a class="btn secondary" href="#timeline">Replay</a>
      <a class="btn secondary" href="#patch">Review patch</a>
      <a class="btn secondary" href="#denied">Denied writes</a>
		{{if .HasCheckpoint}}{{if .ActiveSentinel}}<span class="btn secondary disabled" aria-disabled="true">Rollback unavailable</span>{{else}}<a class="btn secondary" href="#rollback">{{if .ReadOnly}}Rollback instructions{{else}}{{if .InPlace}}Restore touched paths{{else}}Restore workspace{{end}}{{end}}</a>{{end}}{{end}}
      <a class="btn secondary" href="#review">{{if .ReadOnly}}Review command{{else}}Review{{end}}</a>
      <a class="btn secondary" href="/api/runs/{{.RunID}}/verify" target="_blank">Verify status ↗</a>
    </div>
    {{if .ReadOnly}}<div class="hint" style="margin-top:8px"># read-only viewer — review, rollback and export change state, so they run as terminal commands (shown in each section below)</div>{{end}}
  </div>
</div>

<!-- ── What should I do next? ── -->
{{if .NextStep.Headline}}
<div class="section next-step {{nsClass .NextStep.Class}}">
  <h2>What should I do next?</h2>
  <p class="ns-headline">{{.NextStep.Headline}}</p>
  <p class="ns-detail">{{.NextStep.Detail}}</p>
  {{if .NextStep.Command}}<pre>{{.NextStep.Command}}</pre>{{end}}
</div>
{{end}}

<!-- ── Run metadata ── -->
<div class="section">
  <h2>Run details</h2>
  <div class="grid">
    <div class="field"><div class="k">Adapter</div><div class="v">{{.Manifest.Adapter.Name}}</div></div>
    <div class="field"><div class="k">Sandbox</div><div class="v">{{.Manifest.Sandbox.Mode}}</div></div>
    <div class="field"><div class="k">Network</div><div class="v">{{.Manifest.Network.Mode}}</div></div>
    <div class="field"><div class="k">Mode</div><div class="v">{{.Manifest.ExecutionMode}}</div></div>
    {{if .IsSentinel}}<div class="field"><div class="k">Repository</div><div class="v mono" title="{{.Manifest.WorkspacePath}}">{{.Manifest.WorkspacePath}}</div></div>
    <div class="field"><div class="k">Session status</div><div class="v">{{if .ActiveSentinel}}active{{else}}{{if .Manifest.Status.Terminal}}{{.Manifest.Status.Terminal}}{{else}}stopped{{end}}{{end}}</div></div>{{end}}
    <div class="field"><div class="k">Policy pack</div><div class="v">{{if .Manifest.PolicyPack.Name}}{{.Manifest.PolicyPack.Name}}{{else}}—{{end}}</div></div>
    <div class="field"><div class="k">Target</div><div class="v">{{if .Manifest.Execution.Target}}{{.Manifest.Execution.Target}}{{else}}local{{end}}</div></div>
  </div>
  {{if .Manifest.Invocation.DisplayCommand}}
  <div style="margin-top:12px">
    <div class="k" style="font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:4px">Command</div>
    <pre>{{.Manifest.Invocation.DisplayCommand}}</pre>
  </div>
  {{end}}
</div>

<!-- ── Effective policy ── -->
<div class="section" id="policy">
  <h2>Effective policy</h2>
  <div class="grid">
    <div class="field"><div class="k">Policy pack</div><div class="v">{{if .Policy.Pack}}{{.Policy.Pack}}{{else}}—{{end}}</div></div>
    <div class="field"><div class="k">Network</div><div class="v">{{if .Policy.Network}}{{.Policy.Network}}{{else}}off{{end}}</div></div>
    <div class="field"><div class="k">Sandbox</div><div class="v">{{if .Policy.Sandbox}}{{.Policy.Sandbox}}{{else}}—{{end}}</div></div>
    <div class="field"><div class="k">Env allowlist</div><div class="v">{{if .Policy.EnvAllowlist}}{{len .Policy.EnvAllowlist}} variable(s){{else}}none{{end}}</div></div>
    <div class="field"><div class="k">Deny rules</div><div class="v">{{if .Policy.HasDenyRules}}{{len .Policy.DenyRules}} configured{{else}}none configured{{end}}</div></div>
  </div>
  {{if .Policy.HasDenyRules}}
  <details style="margin-top:10px"><summary class="small">Configured deny rules ({{len .Policy.DenyRules}})</summary>
    <ul style="margin:6px 0;padding-left:18px">{{range .Policy.DenyRules}}<li class="mono small">{{.}}</li>{{end}}</ul>
  </details>
  {{else}}
  <div class="caveat" style="margin-top:10px">
    No explicit path deny rules are configured. Files such as <span class="mono">.env</span> are not automatically blocked unless your effective policy defines a matching deny rule.
    <div class="hint" style="margin-top:6px">airlock policy show</div>
  </div>
  {{end}}
</div>

<!-- ── Replay (playback) ── -->
<div class="section" id="timeline">
  <h2>Replay summary</h2>
  <p class="muted" style="margin:0 0 10px;font-size:13px">A plain-language playback of what happened, grouped by phase. The full raw event stream is available at the bottom for drilldown.</p>
  <div class="replay-counts">
    <div class="replay-chip"><span class="n">{{.ReplaySummary.Setup}}</span><span class="l">setup &amp; sandbox</span></div>
    <div class="replay-chip"><span class="n">{{.ReplaySummary.AllowedChanges}}</span><span class="l">allowed changes</span></div>
    <div class="replay-chip"><span class="n">{{.ReplaySummary.DeniedReverted}}</span><span class="l">denied / reverted</span></div>
    <div class="replay-chip"><span class="n">{{.ReplaySummary.BlockedCommands}}</span><span class="l">blocked commands</span></div>
    <div class="replay-chip"><span class="n">{{.ReplaySummary.RollbackEvents}}</span><span class="l">rollback events</span></div>
    <div class="replay-chip"><span class="n">{{.ReplaySummary.EvidenceArtifacts}}</span><span class="l">evidence artifacts</span></div>
  </div>

  {{if gt .ReplaySummary.EnvExcluded 0}}
  <div class="envnote">
    <strong>Environment guardrail:</strong> {{.ReplaySummary.EnvExcluded}} environment variable(s) excluded from the sandbox. This is expected hardening, not a policy violation.
    <details style="margin-top:6px"><summary>Show excluded variables</summary>
      <div class="mono small" style="margin-top:6px;line-height:1.8">{{range .ReplaySummary.EnvKeys}}{{.}} {{end}}</div>
    </details>
  </div>
  {{end}}

  {{if .ReplayGroups}}
    {{range .ReplayGroups}}
    <div class="replay-group">
      <div class="gname">{{.Name}}</div>
      {{range .Steps}}
      <div class="step {{stepClass .Status}}">
        <div class="stephead">
          <div class="steplabel">
            {{if eq .Status "blocked"}}⛔ {{end}}{{if eq .Status "rollback"}}↩ {{end}}{{.Label}}
          </div>
          <div class="steptime">{{.TS}}</div>
        </div>
        {{if .Summary}}<div class="stepsummary">{{.Summary}}</div>{{end}}
        {{if .Path}}<div class="steppath">{{.Path}}</div>{{end}}
        {{if .Diff}}<details><summary>Diff preview</summary><pre>{{.Diff}}</pre></details>{{end}}
        {{if .Detail}}<details><summary>Details</summary><pre>{{.Detail}}</pre></details>{{end}}
      </div>
      {{end}}
    </div>
    {{end}}
  {{else}}
    <div class="muted">No timeline events found. Run <span class="mono">airlock replay {{.RunID}}</span> in the terminal.</div>
  {{end}}

  {{if .Steps}}
  <details style="margin-top:14px">
    <summary>Raw event timeline ({{len .Steps}} events)</summary>
    <div style="margin-top:8px">
    {{range .Steps}}
      <div class="step {{stepClass .Status}}">
        <div class="stephead">
          <div class="steplabel">{{if eq .Status "blocked"}}⛔ {{end}}{{if eq .Status "rollback"}}↩ {{end}}{{.Label}}</div>
          <div class="steptime">{{.TS}}</div>
        </div>
        {{if .Summary}}<div class="stepsummary">{{.Summary}}</div>{{end}}
        {{if .Path}}<div class="steppath">{{.Path}}</div>{{end}}
        {{if .Detail}}<details><summary>Details</summary><pre>{{.Detail}}</pre></details>{{end}}
      </div>
    {{end}}
    </div>
  </details>
  {{end}}
</div>

<!-- ── Patch ── -->
<div class="section" id="patch">
  <h2>Patch review</h2>
  <div class="muted">{{.PatchSummary}}</div>
  {{if .PatchFiles}}
    <ul style="margin:8px 0;padding-left:18px">
      {{range .PatchFiles}}<li class="mono">{{.}}</li>{{end}}
    </ul>
  {{else}}
    <div class="muted" style="margin-top:8px">No file changes detected in this run.</div>
  {{end}}
  {{if .PatchPreview}}<details style="margin-top:8px"><summary>Preview diff</summary><pre>{{.PatchPreview}}</pre></details>{{else}}<div class="muted hint">No patch artifact — run: airlock patch {{.RunID}}</div>{{end}}
</div>

<!-- ── Denied writes ── -->
<div class="section" id="denied">
  <h2>Denied / reverted writes</h2>
  {{if .DeniedItems}}
	<table>
		<tr><th>Path</th><th>Risk</th><th>Decision</th><th>Reason</th></tr>
    {{range .DeniedItems}}
    <tr class="deny-row">
      <td>
        <div class="mono">{{if .Path}}{{.Path}}{{else}}—{{end}}</div>
        {{if .Explanation}}<div class="deny-explanation">{{.Explanation}}</div>{{end}}
      </td>
			<td>{{if .Risk}}<span class="badge {{riskClass .Risk}}">{{.Risk}}</span>{{else}}—{{end}}</td>
			<td>{{if eq .RevertState "reverted"}}<span class="badge ok">DENY → REVERTED</span>{{else if eq .RevertState "failed"}}<span class="badge bad" title="{{.RevertError}}">DENY → REVERT FAILED</span>{{else}}<span class="badge bad">DENY</span>{{end}}</td>
			<td class="mono">{{if .Reason}}{{.Reason}}{{else}}policy deny{{end}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <div class="muted">No denied writes recorded in this run.</div>
  {{end}}
</div>

<!-- ── Rollback ── -->
{{if .Rollback}}
<div class="section rollback-section" id="rollback">
  <h2>↩ Workspace rolled back</h2>
  <div class="badges" style="margin-bottom:12px">
    <span class="badge warn">{{.Rollback.Mode}} restore</span>
    <span class="badge warn">status: {{.Rollback.Status}}</span>
    <span class="badge {{reviewClass .Review.State}}">review: {{.Review.State}}</span>
    <span class="badge {{verifyClass .Verify.Status}}">{{.Verify.Status}}</span>
  </div>
  <div class="grid" style="margin-bottom:10px">
    <div class="field"><div class="k">Mode</div><div class="v">{{.Rollback.Mode}}</div></div>
    <div class="field"><div class="k">Checkpoint</div><div class="v mono">{{.Rollback.Checkpoint}}</div></div>
    <div class="field"><div class="k">Status</div><div class="v">{{.Rollback.Status}}</div></div>
    <div class="field"><div class="k">Timestamp</div><div class="v mono small">{{.Rollback.Timestamp}}</div></div>
  </div>
  {{if .Rollback.Paths}}
  <div style="margin-bottom:10px">
    <div class="k" style="font-size:11px;text-transform:uppercase;color:var(--muted);margin-bottom:4px">Paths restored</div>
    <ul style="margin:4px 0;padding-left:18px">{{range .Rollback.Paths}}<li class="mono">{{.}}</li>{{end}}</ul>
  </div>
  {{end}}
  <div class="caveat">
    {{if .InPlace}}
    <strong>What rollback restored:</strong> the recorded touched paths in the real repository at <span class="mono">{{.Manifest.WorkspacePath}}</span> from checkpoint cp-0.
    {{else}}
    <strong>What rollback restored:</strong> the <em>Airlock workspace</em> at
    <span class="mono">.airlock/workspaces/{{.RunID}}/repo</span> — the isolated copy the agent ran in.
    <br>Rollback restores the Airlock workspace, <strong>not your original repo</strong>. Your original source directory was not modified at any point by Airlock.
    {{end}}
    <br>Review state is now <strong>needs-attention</strong> — this run requires re-review before approving.
    Digest was rebuilt after rollback; run <span class="mono">airlock verify {{.RunID}}</span> to confirm integrity.
    <br>Use the patch / export / review workflow before applying any changes back to your source.
    Operation-level rollback (undo last N operations) is future work.
  </div>
</div>
{{else if .Manifest.Checkpoints}}
{{if .ActiveSentinel}}
<div class="section rollback-section" id="rollback">
  <h2>Rollback unavailable while Sentinel is active</h2>
  <p class="muted" style="margin:0 0 10px;font-size:14px">Stop Sentinel before rollback. Restorative writes are filesystem mutations and an active watcher would observe and re-evaluate them.</p>
  <button class="btn disabled" type="button" disabled aria-disabled="true">Restore checkpoint</button>
  <span class="btn-label">Stop Sentinel before rollback</span>
</div>
{{else}}
<div class="section" id="rollback">
  <h2>{{if .ReadOnly}}Rollback instructions — checkpoint cp-0{{else}}Rollback available — restore workspace from cp-0{{end}}</h2>
  {{if .InPlace}}
  <p class="muted" style="margin:0 0 10px;font-size:14px">Airlock captured a checkpoint before this in-place session. Rollback restores only this session's touched paths in the real repository.</p>
  <div class="grid" style="margin-bottom:10px">
    <div class="field"><div class="k">Repository</div><div class="v small mono">{{.Manifest.WorkspacePath}}</div></div>
    <div class="field"><div class="k">Restore scope</div><div class="v small">{{len .Manifest.TouchedPaths}} touched path(s)</div></div>
    <div class="field"><div class="k">Checkpoint</div><div class="v small mono">.airlock/runs/{{.RunID}}/checkpoints/cp-0</div></div>
  </div>
  {{else}}
  <p class="muted" style="margin:0 0 10px;font-size:14px">Airlock captured a checkpoint before the agent ran. You can restore the isolated Airlock workspace to that checkpoint. This does not modify your original repo.</p>
  <div class="grid" style="margin-bottom:10px">
    <div class="field"><div class="k">Original repo</div><div class="v small">Your source directory — never touched by Airlock or rollback.</div></div>
    <div class="field"><div class="k">Airlock workspace</div><div class="v small mono">.airlock/workspaces/{{.RunID}}/repo</div></div>
    <div class="field"><div class="k">Checkpoint</div><div class="v small mono">.airlock/runs/{{.RunID}}/checkpoints/cp-0</div></div>
  </div>
  {{end}}
  <div class="hint" style="margin-top:4px"># 1. preview what would be restored (no changes made — always start here):
./airlock rollback {{.RunID}} --dry-run

# 2. restore full workspace to checkpoint cp-0:
./airlock rollback {{.RunID}} --force

# 3. restore a single path only:
./airlock rollback {{.RunID}} --path src/changed-file.txt --force</div>
  <div class="caveat">
    {{if .InPlace}}
    <strong>Rollback modifies the real repository.</strong> It restores only paths touched during this in-place session from checkpoint cp-0; unrelated paths and Git history are left alone.
    {{else}}
    <strong>Rollback restores the Airlock workspace, not your original repo.</strong>
    It rewinds <span class="mono">.airlock/workspaces/{{.RunID}}/repo</span> to checkpoint cp-0. Your original source directory is never modified by Airlock.
    {{end}}
    <br>Use the patch / export / review workflow before applying any changes back to your source.
    After rollback: review state becomes needs-attention, digest is rebuilt, report is regenerated.
    Operation-level rollback (last N operations) is future work.
  </div>
  {{if not .ReadOnly}}
	<form method="post" action="/api/runs/{{.RunID}}/rollback" style="margin-top:12px" onsubmit="if(!confirm('Restore this session from checkpoint cp-0?\n\nUse the restore scope shown above to confirm what will be modified.\nReview will reset to needs-attention.\n\nProceed?')){return false;} var b=document.getElementById('rollback-btn'); b.disabled=true; b.textContent='Restoring…'; var n=document.getElementById('rollback-pending'); if(n){n.style.display='block';} return true;">
    <label style="font-size:13px">checkpoint
      <select name="checkpoint">
        {{range .Manifest.Checkpoints}}<option value="{{.ID}}">{{.ID}}</option>{{end}}
      </select>
    </label>
    <button class="btn" id="rollback-btn" type="submit" style="margin-left:8px">Restore workspace</button>
    <div class="small" id="rollback-pending" style="display:none;margin-top:8px;color:var(--muted)">Running rollback…</div>
    <div class="hint" style="margin-top:6px"># operator mode — runs the same rollback as the CLI; affects the Airlock workspace only, your original repo is untouched</div>
  </form>
  {{end}}
  {{if .ReadOnly}}<div class="hint" style="margin-top:8px"># read-only viewer — run one of the rollback commands above in a terminal</div>{{end}}
  <div class="small" style="margin-top:10px;color:var(--muted)">After running a rollback command, this page will update automatically or show a refresh notice.</div>
</div>
{{end}}
{{else}}
<div class="section" id="rollback">
  <h2>Rollback</h2>
  <div class="muted">No checkpoint available for this run.</div>
</div>
{{end}}

<!-- ── Review ── -->
<div class="section" id="review">
  <h2>Review decision</h2>
  <div class="badges" style="margin-bottom:8px">
    <span class="badge {{reviewClass .Review.State}}">{{if .Review.State}}{{.Review.State}}{{else}}unreviewed{{end}}</span>
  </div>
  {{if eq .Review.State "unreviewed"}}
  <div class="muted">Unreviewed — this run has not been approved or rejected.</div>
  <div class="hint">airlock review {{.RunID}} --state approved --note "looks clean"</div>
  {{else}}
  <div class="grid" style="margin-bottom:8px">
    <div class="field"><div class="k">Reviewer</div><div class="v">{{if .Review.Reviewer}}{{.Review.Reviewer}}{{else}}—{{end}}</div></div>
    <div class="field"><div class="k">Timestamp</div><div class="v mono small">{{.Review.Timestamp}}</div></div>
  </div>
  {{if .Review.Note}}<div><span class="k" style="font-size:11px;text-transform:uppercase;color:var(--muted)">Note</span><div>{{.Review.Note}}</div></div>{{end}}
  {{end}}
  {{if .ReadOnly}}
  <div class="hint" style="margin-top:10px"># read-only viewer — update via terminal: airlock review {{.RunID}} --state approved</div>
  {{else}}
  <form method="post" action="/api/runs/{{.RunID}}/review" style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <select name="state"><option>approved</option><option>rejected</option><option>needs-attention</option><option>unreviewed</option></select>
    <input name="reviewer" placeholder="reviewer" style="width:140px">
    <input name="note" placeholder="short note" style="width:220px">
    <button class="btn" type="submit">Update review</button>
  </form>
  {{end}}
</div>

<!-- ── Export ── -->
<div class="section" id="export">
  <h2>Export evidence bundle</h2>
  {{if .Manifest.Export.Path}}
  <div class="mono">{{.Manifest.Export.Path}}</div>
  <div class="hint" style="margin-top:6px"># re-export: airlock export {{.RunID}} --format zip --include-report</div>
  {{else}}
  <div class="muted">No export artifact yet.</div>
  <div class="hint" style="margin-top:6px">airlock export {{.RunID}} --format zip --include-report</div>
  {{end}}
</div>

<!-- ── Session timeline ── -->
<div class="section">
  <h2>Session trace</h2>
  {{if .SessionEvents}}
    {{range .SessionEvents}}<div class="muted small">[{{.TS}}] <span class="mono">{{.Type}}</span> {{.Content}}</div>{{end}}
  {{else}}
    <div class="muted">No session trace available for this adapter.</div>
    <div class="hint"># generic-shell adapter captures process-level evidence only (commands, file events, policy decisions)</div>
  {{end}}
</div>

<div class="small mono" style="margin-top:16px;color:var(--muted)">run_id: {{.RunID}} · <a href="/">all runs</a></div>
</div>
<script>
(function(){
  var b=document.body, runId=b.dataset.runId, base=b.dataset.fingerprint;
  // Strip the one-shot ?rollback flash from the URL so auto-refresh reloads and
  // manual refreshes don't keep re-showing the banner (it already rendered).
  try{if(/[?&]rollback=/.test(location.search)){history.replaceState(null,"",location.pathname+location.hash);}}catch(e){}
  var statusEl=document.getElementById("refresh-status");
  var checkedEl=document.getElementById("last-checked");
  var banner=document.getElementById("update-banner");
  var failures=0;
  function pad(n){return n<10?"0"+n:""+n;}
  function now(){var d=new Date();return pad(d.getHours())+":"+pad(d.getMinutes())+":"+pad(d.getSeconds());}
  function poll(){
    fetch("/api/runs/"+encodeURIComponent(runId)+"/state",{cache:"no-store"})
      .then(function(r){return r.ok?r.json():Promise.reject(r.status);})
      .then(function(s){
        failures=0;
        if(checkedEl)checkedEl.textContent=now();
        if(s&&s.fingerprint&&s.fingerprint!==base){
          if(banner)banner.classList.add("show");
          if(statusEl)statusEl.textContent="updating…";
          setTimeout(function(){location.reload();},700);
        }
      })
      .catch(function(){
        failures++;
        if(failures>=3&&statusEl)statusEl.textContent="paused (viewer offline)";
      });
  }
  poll();
  setInterval(poll,3000);
})();
function toggleViewerPanel(){
  var panel=document.getElementById("viewer-panel");
  if(!panel)return;
  if(panel.style.display!=="none"){panel.style.display="none";return;}
  panel.style.display="block";
  loadViewerPanel();
}
function loadViewerPanel(){
  var body=document.getElementById("viewer-panel-body");
  if(!body)return;
  body.innerHTML="Loading&#8230;";
  fetch("/api/viewer",{cache:"no-store"})
    .then(function(r){return r.ok?r.json():Promise.reject(r.status);})
    .then(function(d){renderViewerPanel(d,body);})
    .catch(function(){body.innerHTML="<span style='color:#ef4444'>Could not reach viewer API.</span>";});
}
function renderViewerPanel(d,body){
  var ro=document.body.dataset.readonly==="1";
  if(!d.running){body.innerHTML="<div style='color:#64748b;text-align:center;padding:8px 0'>No viewer running.</div>";return;}
  var rows="";
  rows+="<div style='display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>mode</span><span style='font-weight:600'>"+(d.mode||"&#8212;")+"</span></div>";
  rows+="<div style='display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>URL</span><span><a href='"+(d.url||"#")+"' style='color:#0284c7'>"+(d.url||"&#8212;")+"</a></span></div>";
  rows+="<div style='display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>uptime</span><span>"+(d.uptime||"&#8212;")+"</span></div>";
  rows+="<div style='display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>PID</span><span>"+(d.pid||"&#8212;")+"</span></div>";
  if(d.log){rows+="<div style='padding:4px 0;border-bottom:1px solid #f1f5f9'><span style='color:#64748b'>log&nbsp;</span><span style='font-size:11px;word-break:break-all;color:#64748b'>"+d.log+"</span></div>";}
  var btns="<div style='margin-top:12px;display:flex;gap:8px;flex-wrap:wrap'>";
  btns+="<button onclick='loadViewerPanel()' style='font-size:12px;background:#334155;border:none;color:#fff;padding:4px 10px;border-radius:6px;cursor:pointer'>Refresh</button>";
  if(!ro){btns+="<button onclick='stopViewer()' style='font-size:12px;background:#dc2626;border:none;color:#fff;padding:4px 10px;border-radius:6px;cursor:pointer'>Stop Viewer</button>";}
  btns+="</div>";
  body.innerHTML=rows+btns;
}
function stopViewer(){
  if(!confirm("Stop the Airlock viewer?\n\nThis will shut down the local HTTP server. You can restart it with:\n\n  airlock serve --background --open"))return;
  var body=document.getElementById("viewer-panel-body");
  if(body)body.innerHTML="Stopping&#8230;";
  fetch("/api/viewer/stop",{method:"POST",cache:"no-store"})
    .then(function(r){return r.ok?r.text():Promise.reject(r.status);})
    .then(function(html){document.open();document.write(html);document.close();})
    .catch(function(e){if(body)body.innerHTML="<span style='color:#ef4444'>Stop failed ("+e+"). Try: airlock serve --stop</span>";});
}
document.addEventListener("click",function(e){
  var wrap=document.getElementById("viewer-chip-wrap");
  var panel=document.getElementById("viewer-panel");
  if(wrap&&panel&&!wrap.contains(e.target)&&panel.style.display!=="none"){panel.style.display="none";}
});
</script>
</body></html>`))

	patchPreview := ""
	if runmeta.Exists(a.PatchPath) {
		if b, err := osReadFileLimited(a.PatchPath, 14000); err == nil {
			patchPreview = string(b)
		}
	}

	pol := policyView{
		Pack:         a.Manifest.PolicyPack.Name,
		Network:      a.Manifest.PolicySummary.Network,
		Sandbox:      a.Manifest.Sandbox.Mode,
		EnvAllowlist: a.Manifest.Env.Allowed,
		DenyRules:    a.Manifest.PolicySummary.DenyWrite,
		AllowRules:   a.Manifest.PolicySummary.AllowWrite,
		HasDenyRules: len(a.Manifest.PolicySummary.DenyWrite) > 0,
	}

	data := map[string]any{
		"RunID":              runID,
		"Manifest":           a.Manifest,
		"Review":             rv, // reviewView with plain string fields, not review.Record
		"Verify":             vr,
		"Card":               card,
		"Steps":              steps,
		"PatchFiles":         patchSummary.Files,
		"PatchSummary":       patchSummary.Summary,
		"PatchPreview":       patchPreview,
		"SessionEvents":      a.SessionEvents,
		"ReadOnly":           s.readOnly,
		"Rollback":           rollbackData,
		"DeniedItems":        deniedItems,
		"GovernanceSentence": sentence,
		"NextStep":           ns,
		"ReplaySummary":      replaySum,
		"ReplayGroups":       replayGroups,
		"HasCheckpoint":      hasCheckpoint,
		"Fingerprint":        liveState.Fingerprint,
		"Updated":            liveState.Updated,
		"RollbackState":      rollbackState,
		"RollbackFlash":      rollbackFlash,
		"RollbackReason":     rollbackReason,
		"Policy":             pol,
		"IsSentinel":         isSentinel,
		"InPlace":            inPlace,
		"ActiveSentinel":     activeSentinel,
	}

	// Buffer template execution so a type-mismatch or other template error never
	// sends a partial HTML body. On error, return a readable error page instead.
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		log.Printf("web: handleRunPage template error for run %s: %v", runID, err)
		http.Error(w, fmt.Sprintf("Evidence viewer error for run %s\n\nDetails: %v\n\nRaw artifacts are still intact — use:\n  ./airlock inspect %s\n  ./airlock replay %s\n  ./airlock verify %s", runID, err, runID, runID, runID), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *Server) handleComparePage(w http.ResponseWriter, r *http.Request) {
	aID := r.URL.Query().Get("a")
	bID := r.URL.Query().Get("b")
	if aID == "" || bID == "" {
		http.Error(w, "use /compare?a=<run>&b=<run>", http.StatusBadRequest)
		return
	}
	a, err := runmeta.LoadArtifacts(aID)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	b, err := runmeta.LoadArtifacts(bID)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	t := template.Must(template.New("cmp").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Compare</title>
<style>body{font-family:ui-sans-serif,system-ui,-apple-system;margin:24px;background:#f8fafc}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:10px;overflow:hidden}th,td{padding:10px;border-bottom:1px solid #e5e7eb;text-align:left}th{background:#f9fafb}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}</style></head><body>
<h1>Run Compare</h1>
<div class="mono">A={{.A.RunID}} | B={{.B.RunID}}</div>
<table>
  <tr><th>Metric</th><th>Run A</th><th>Run B</th><th>Delta</th></tr>
  <tr><td>High risk</td><td>{{.A.Manifest.RiskSummary.HighCount}}</td><td>{{.B.Manifest.RiskSummary.HighCount}}</td><td>{{if gt .B.Manifest.RiskSummary.HighCount .A.Manifest.RiskSummary.HighCount}}increased{{else if lt .B.Manifest.RiskSummary.HighCount .A.Manifest.RiskSummary.HighCount}}decreased{{else}}unchanged{{end}}</td></tr>
  <tr><td>Denied actions</td><td>{{.A.Manifest.ApprovalSummary.DeniedCount}}</td><td>{{.B.Manifest.ApprovalSummary.DeniedCount}}</td><td>{{if gt .B.Manifest.ApprovalSummary.DeniedCount .A.Manifest.ApprovalSummary.DeniedCount}}increased{{else if lt .B.Manifest.ApprovalSummary.DeniedCount .A.Manifest.ApprovalSummary.DeniedCount}}decreased{{else}}unchanged{{end}}</td></tr>
  <tr><td>Touched paths</td><td>{{len .A.Manifest.TouchedPaths}}</td><td>{{len .B.Manifest.TouchedPaths}}</td><td>{{if gt (len .B.Manifest.TouchedPaths) (len .A.Manifest.TouchedPaths)}}increased{{else if lt (len .B.Manifest.TouchedPaths) (len .A.Manifest.TouchedPaths)}}decreased{{else}}unchanged{{end}}</td></tr>
  <tr><td>Denied paths</td><td>{{len .A.Manifest.DeniedPaths}}</td><td>{{len .B.Manifest.DeniedPaths}}</td><td>{{if gt (len .B.Manifest.DeniedPaths) (len .A.Manifest.DeniedPaths)}}increased{{else if lt (len .B.Manifest.DeniedPaths) (len .A.Manifest.DeniedPaths)}}decreased{{else}}unchanged{{end}}</td></tr>
  <tr><td>Signed</td><td>{{.A.Manifest.Digest.Signed}}</td><td>{{.B.Manifest.Digest.Signed}}</td><td>{{if ne .A.Manifest.Digest.Signed .B.Manifest.Digest.Signed}}changed{{else}}unchanged{{end}}</td></tr>
</table>
</body></html>`))
	_ = t.Execute(w, map[string]any{"A": a, "B": b})
}

// handleFiles serves raw artifacts from a run directory (report HTML, patch,
// manifest, etc). Paths are cleaned and confined to .airlock/runs/<id>.
func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/files/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "not found: specify /files/<run_id>/<artifact>", http.StatusNotFound)
		return
	}
	runID := parts[0]
	if _, err := runmeta.LoadArtifacts(runID); err != nil {
		http.Error(w, "run not found: "+runID, http.StatusNotFound)
		return
	}
	sub := "report/index.html"
	if len(parts) == 2 && parts[1] != "" {
		sub = parts[1]
	}
	runDir := filepath.Join(".airlock", "runs", runID)
	clean := filepath.Clean(filepath.Join(runDir, sub))
	if !strings.HasPrefix(clean, filepath.Clean(runDir)+string(filepath.Separator)) && clean != filepath.Clean(runDir) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(clean); err != nil {
		http.Error(w, "artifact not found: "+sub+" (run may predate report generation)", http.StatusNotFound)
		return
	}
	// http.ServeFile 301-redirects paths ending in index.html; serve HTML
	// directly so the static report opens without a redirect dance.
	if strings.HasSuffix(clean, ".html") {
		b, err := os.ReadFile(clean)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
		return
	}
	http.ServeFile(w, r, clean)
}

func (s *Server) handleAPIRuns(w http.ResponseWriter, r *http.Request) {
	store := loadIndex()
	writeJSON(w, store.Runs)
}

func (s *Server) handleAPIRunRoutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	runID := parts[0]
	a, err := runmeta.LoadArtifacts(runID)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	if len(parts) == 1 {
		writeJSON(w, a)
		return
	}
	switch parts[1] {
	case "events":
		writeJSON(w, a.Events)
	case "session":
		writeJSON(w, a.SessionEvents)
	case "patch":
		if !runmeta.Exists(a.PatchPath) {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, a.PatchPath)
	case "review":
		if r.Method == http.MethodGet {
			rev, _ := review.Load(a.RunDir)
			writeJSON(w, rev)
			return
		}
		if s.readOnly {
			http.Error(w, "read-only", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		rec, err := parseReviewRequest(r)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if rec.Reviewer == "" {
			rec.Reviewer = "web"
		}
		rec.Timestamp = time.Now().UTC().Format(time.RFC3339)
		if err := review.Save(a.RunDir, rec); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		store, _ := index.Rebuild(".airlock/runs")
		_ = index.Save(index.DefaultPath(), store)
		writeJSON(w, rec)
	case "rollback":
		if s.readOnly {
			http.Error(w, "read-only", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		if s.sentinelRollbackBlocked(a.Manifest) {
			reason := "Stop Sentinel before rollback"
			http.Redirect(w, r, "/runs/"+runID+"?rollback=error&reason="+url.QueryEscape(reason)+"#rollback", http.StatusSeeOther)
			return
		}
		checkpoint := strings.TrimSpace(r.FormValue("checkpoint"))
		if checkpoint == "" {
			checkpoint = "cp-0"
		}
		restorePath := strings.TrimSpace(r.FormValue("path"))
		// Operator-mode rollback runs the same shared implementation as the CLI
		// (internal/rollback), not a subprocess — one honest code path.
		if _, err := rollback.Execute(rollback.Options{RunID: runID, Checkpoint: checkpoint, Path: restorePath}); err != nil {
			// Visible failure: log it (to viewer.log in background mode) and send
			// the operator back to a page that renders a red error banner.
			log.Printf("web: rollback failed for run %s: %v", runID, err)
			http.Redirect(w, r, "/runs/"+runID+"?rollback=error&reason="+url.QueryEscape(err.Error())+"#rollback", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/runs/"+runID+"?rollback=success#rollback", http.StatusSeeOther)
	case "verify":
		res, _ := runmeta.VerifyRun(runID, a.Manifest)
		writeJSON(w, res)
	case "state":
		writeJSON(w, computeRunState(a))
	default:
		http.NotFound(w, r)
	}
}

// handleAPIViewer returns the live viewer metadata from .airlock/viewer.json plus
// computed uptime and the polling interval. Used by the in-browser status panel.
func (s *Server) handleAPIViewer(w http.ResponseWriter, r *http.Request) {
	b, err := os.ReadFile(filepath.Join(".airlock", "viewer.json"))
	if err != nil {
		writeJSON(w, map[string]any{"running": false})
		return
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		writeJSON(w, map[string]any{"running": false})
		return
	}
	if started, ok := m["started"].(string); ok {
		if t, err := time.Parse(time.RFC3339, started); err == nil {
			m["uptime"] = formatUptime(time.Since(t))
		}
	}
	m["running"] = true
	m["pollIntervalSec"] = 3
	writeJSON(w, m)
}

// handleAPIViewerStop (operator only) writes a clean shutdown page, then exits
// the viewer process after a brief delay so the response is fully flushed.
func (s *Server) handleAPIViewerStop(w http.ResponseWriter, r *http.Request) {
	if s.readOnly {
		http.Error(w, "read-only", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, viewerShutdownPage)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		// Remove metadata so --status stays accurate after the process exits.
		_ = os.Remove(filepath.Join(".airlock", "viewer.json"))
		_ = os.Remove(filepath.Join(".airlock", "viewer.pid"))
		if s.shutdownFunc != nil {
			s.shutdownFunc()
		} else {
			os.Exit(0)
		}
	}()
}

func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

const viewerShutdownPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Airlock Viewer — Stopped</title>
<style>
*{box-sizing:border-box}
body{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;margin:0;background:#f6f8fa;color:#1f2328;display:flex;align-items:center;justify-content:center;min-height:100vh}
.box{text-align:center;padding:48px 32px;max-width:480px}
.tag{display:inline-block;background:#dafbe1;border:1px solid #2da44e;border-radius:999px;padding:3px 14px;font-size:13px;color:#1a7f37;margin-bottom:20px;font-weight:600}
h1{font-size:26px;margin:0 0 12px;font-weight:700}
p{color:#656d76;margin:8px 0;line-height:1.6;font-size:15px}
pre{display:inline-block;background:#1f2328;color:#e6edf3;padding:12px 20px;border-radius:10px;font-size:14px;margin:18px 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.note{color:#94a3b8;font-size:13px;margin-top:12px}
</style></head>
<body><div class="box">
  <div class="tag">✓ Stopped cleanly</div>
  <h1>Airlock Viewer stopped.</h1>
  <p>The local viewer has exited successfully.</p>
  <p>No evidence, runs, workspaces, or artifacts were modified.</p>
  <pre>airlock serve --background --open</pre>
  <p class="note">Close this browser tab whenever you're ready.</p>
</div></body></html>`

// handleAPIState returns a lightweight snapshot of every run's live state plus a
// global fingerprint. The run-list page polls this to auto-refresh when runs are
// created or their review/rollback/export/verify state changes.
func (s *Server) handleAPIState(w http.ResponseWriter, r *http.Request) {
	states, fingerprint := computeGlobalState()
	writeJSON(w, map[string]any{
		"count":       len(states),
		"updated":     time.Now().UTC().Format(time.RFC3339),
		"fingerprint": fingerprint,
		"runs":        states,
	})
}

// computeGlobalState returns each run's live state and a single fingerprint that
// changes whenever any run is added or its review/verify/rollback/export/digest
// state changes. Shared by the run-list page (embedded) and /api/state (polled).
func computeGlobalState() (states []runState, fingerprint string) {
	store := loadIndex()
	states = make([]runState, 0, len(store.Runs))
	var fp strings.Builder
	for _, e := range store.Runs {
		a, err := runmeta.LoadArtifacts(e.RunID)
		if err != nil {
			continue
		}
		st := computeRunState(a)
		states = append(states, st)
		fp.WriteString(st.RunID)
		fp.WriteByte(':')
		fp.WriteString(st.Fingerprint)
		fp.WriteByte(';')
	}
	return states, fmt.Sprintf("%d|%s", len(states), fp.String())
}

func (s *Server) handleAPICompare(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/compare/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		http.Error(w, "use /api/compare/<a>/<b>", 400)
		return
	}
	a, err := runmeta.LoadArtifacts(parts[0])
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	b, err := runmeta.LoadArtifacts(parts[1])
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	writeJSON(w, map[string]any{
		"a": parts[0], "b": parts[1],
		"risk_high":       map[string]int{"a": a.Manifest.RiskSummary.HighCount, "b": b.Manifest.RiskSummary.HighCount},
		"approval_denied": map[string]int{"a": a.Manifest.ApprovalSummary.DeniedCount, "b": b.Manifest.ApprovalSummary.DeniedCount},
		"touched_paths":   map[string]int{"a": len(a.Manifest.TouchedPaths), "b": len(b.Manifest.TouchedPaths)},
		"signed":          map[string]bool{"a": a.Manifest.Digest.Signed, "b": b.Manifest.Digest.Signed},
	})
}

func webDenyExplanation(reason string) string {
	switch {
	case strings.HasPrefix(reason, "deny_write"):
		return "Path matched a deny_write policy rule. Airlock attempted a best-effort restore of the previous state."
	case strings.HasPrefix(reason, "allow_write"):
		return "Path was not in the allow_write whitelist. Airlock attempted a best-effort restore of the previous state."
	case strings.HasPrefix(reason, "deny_read"):
		return "Path matched a deny_read policy rule. Read was blocked."
	case strings.HasPrefix(reason, "network"):
		return "Network access denied by policy."
	default:
		return "Write was denied by Airlock policy; see the recorded revert result."
	}
}

func webGovernanceSentence(m runmeta.RunManifest, evs []events.Event, hasRollback bool, verifyStatus string) string {
	adapter := m.Adapter.Name
	if adapter == "" {
		adapter = "unknown-adapter"
	}
	sandbox := m.Sandbox.Mode
	if sandbox == "" {
		sandbox = "workspace"
	}

	// Determine if command was blocked before execution.
	cmdBlocked := m.Status.Terminal == "failed" && m.ApprovalSummary.DeniedCount > 0
	for _, e := range evs {
		if e.Type == "RUN_FAILED" {
			if class, ok := e.Meta["class"].(string); ok && class == "policy" {
				cmdBlocked = true
			}
		}
	}

	category := classifyDisplayCategory(adapter, m.Invocation.DisplayCommand, len(m.TouchedPaths) > 0, cmdBlocked)
	allowedChanges := 0
	deniedChanges := 0
	revertFailures := 0
	for _, e := range evs {
		if strings.HasPrefix(e.Type, "FILE_") {
			allowedChanges++
		}
		if e.Type == "POLICY_DENY" || e.Type == "APPROVAL_REQUIRED" {
			deniedChanges++
			failed := false
			if reverted, ok := e.Meta["reverted"].(bool); ok && !reverted {
				failed = true
			}
			if revertErr, ok := e.Meta["revert_error"].(string); ok && revertErr != "" {
				failed = true
			}
			if failed {
				revertFailures++
			}
		}
	}

	var parts []string
	switch category {
	case "Blocked Shell Operation":
		parts = append(parts, fmt.Sprintf("A high-risk command was evaluated by the %s adapter and blocked before execution — no agent code ran and no files were written.", adapter))
	case "BYOM Agent Run":
		parts = append(parts, fmt.Sprintf("A BYOM agent ran via the %s adapter in a %s sandbox.", adapter, sandbox))
	case "Workspace Mutation":
		parts = append(parts, fmt.Sprintf("A process ran via the %s adapter in a %s sandbox and modified workspace files.", adapter, sandbox))
	case "Sentinel Session":
		parts = append(parts, "Persistent Sentinel monitoring observed filesystem activity in the real repository.")
	default:
		parts = append(parts, fmt.Sprintf("A process ran via the %s adapter in a %s sandbox.", adapter, sandbox))
	}

	if cmdBlocked {
		// first sentence already covers the block; no additional detail needed
	} else {
		var details []string
		if allowedChanges > 0 {
			details = append(details, fmt.Sprintf("%d write(s) allowed", allowedChanges))
		}
		if deniedChanges > 0 {
			if revertFailures > 0 {
				details = append(details, fmt.Sprintf("%d write(s) denied (%d revert failure(s))", deniedChanges, revertFailures))
			} else {
				details = append(details, fmt.Sprintf("%d write(s) denied and reverted", deniedChanges))
			}
		}
		if len(details) > 0 {
			parts = append(parts, strings.Join(details, ", ")+".")
		}
	}

	if hasRollback {
		parts = append(parts, "Workspace was subsequently rolled back to checkpoint cp-0.")
	}

	switch verifyStatus {
	case "verified-signed":
		parts = append(parts, "Evidence bundle cryptographically signed and verified.")
	case "verified-unsigned":
		parts = append(parts, "Evidence bundle verified (unsigned — no signing key configured).")
	}

	return strings.Join(parts, " ")
}

// ---- next-step guidance ---------------------------------------------------

type nextStep struct {
	Headline string
	Detail   string
	Command  string
	Class    string // ok | info | warn | bad
}

// computeNextStep produces plain-language "what should I do next?" guidance from
// observable run state. Precedence: verification failure > rollback > denials >
// unreviewed > reviewed-with-checkpoint > done.
func computeNextStep(runID, reviewState, verifyStatus string, hasRollback, hasDenied, hasCheckpoint, readOnly bool) nextStep {
	var ns nextStep
	switch {
	case verifyStatus == "hash-mismatch" || verifyStatus == "signature-invalid":
		ns = nextStep{
			Headline: "Do not trust this evidence yet",
			Detail:   "Verification failed — the recorded digest no longer matches the artifacts on disk. Investigate before relying on this run.",
			Command:  "airlock verify " + runID,
			Class:    "bad",
		}
	case hasRollback:
		// Rollback complete: review is always needs-attention here.
		ns = nextStep{
			Headline: "Re-review required — workspace was rolled back",
			Detail:   "The Airlock workspace was restored to checkpoint cp-0, so review was reset to needs-attention. Re-check the evidence, then approve or reject.",
			Command:  "airlock review " + runID + " --state approved --note \"re-reviewed after rollback\"",
			Class:    "warn",
		}
	case hasDenied && (reviewState == "unreviewed" || reviewState == "needs-attention"):
		ns = nextStep{
			Headline: "Inspect denied writes before approving",
			Detail:   "One or more writes were blocked and reverted by policy. Confirm nothing important was lost, then record a decision.",
			Command:  "airlock inspect " + runID,
			Class:    "warn",
		}
	case reviewState == "unreviewed":
		ns = nextStep{
			Headline: "Review required",
			Detail:   "This run is verified but not yet reviewed. Open the patch, confirm the changes are what you expected, then record a decision.",
			Command:  "airlock review " + runID + " --state approved --note \"looks clean\"",
			Class:    "info",
		}
	case reviewState == "needs-attention":
		ns = nextStep{
			Headline: "Review attention required",
			Detail:   "This run is flagged needs-attention. Re-check the evidence and record an approve or reject decision.",
			Command:  "airlock review " + runID + " --state approved --note \"re-reviewed\"",
			Class:    "warn",
		}
	case reviewState == "rejected":
		ns = nextStep{
			Headline: "Rejected — do not apply",
			Detail:   "This run was reviewed and rejected. Do not apply its changes. If the workspace should be reset, restore it from checkpoint cp-0 (Airlock workspace only).",
			Command:  "airlock rollback " + runID + " --dry-run",
			Class:    "bad",
		}
	case reviewState == "approved":
		ns = nextStep{
			Headline: "Approved — export/apply only if intended",
			Detail:   "This run is approved and its evidence is verified. Export the bundle to share it, or apply the patch to your source if that is intended.",
			Command:  "airlock export " + runID + " --format zip --include-report",
			Class:    "ok",
		}
		if hasCheckpoint && !hasRollback {
			ns.Detail += " A checkpoint is available: use Restore workspace to reset the isolated Airlock workspace to cp-0 (your original repo is never touched)."
		}
	default:
		ns = nextStep{
			Headline: "No action needed",
			Detail:   "This run is reviewed and its evidence is verified. Export the bundle if you need to share it.",
			Command:  "airlock export " + runID + " --format zip --include-report",
			Class:    "ok",
		}
	}
	if readOnly {
		ns.Detail += " You're in read-only mode — run this command in a terminal."
	}
	return ns
}

// ---- replay summary + grouping --------------------------------------------

type replaySummary struct {
	Setup             int
	AllowedChanges    int
	DeniedReverted    int
	BlockedCommands   int
	RollbackEvents    int
	EvidenceArtifacts int
	EnvExcluded       int
	EnvKeys           []string
}

type replayGroup struct {
	Name  string
	Steps []timelineStep
}

var replayGroupOrder = []string{
	"Setup & sandbox", "Agent command", "File changes",
	"Denials & reverts", "Evidence & finish", "Review / rollback", "Other",
}

func replayGroupOf(t string) string {
	switch t {
	case "RUN_START", "ADAPTER_SELECTED", "ADAPTER_PREPARED", "SANDBOX_SELECTED",
		"SANDBOX_NETWORK", "SANDBOX_NETWORK_UNSUPPORTED", "SANDBOX_RUNTIME_SELECTED",
		"SANDBOX_FALLBACK", "CHECKPOINT_CREATED", "MODEL_INFO", "NET_ALLOW", "NET_DENY":
		return "Setup & sandbox"
	case "CMD", "AGENT_STDOUT", "TOOL_CALL", "TOOL_RESULT", "MSG_USER", "MSG_ASSISTANT":
		return "Agent command"
	case "FILE_CREATE", "FILE_WRITE", "FILE_REMOVE":
		return "File changes"
	case "POLICY_DENY", "PATH_DENY", "SECRET_DENY":
		return "Denials & reverts"
	case "PATCH_READY", "PATCH_ERROR", "RUN_DIGEST_READY", "RUN_DIGEST_SIGNED",
		"SESSION_SUMMARY", "RUN_END", "RUN_FAILED":
		return "Evidence & finish"
	case "ROLLBACK", "REVIEW_UPDATED":
		return "Review / rollback"
	default:
		return "Other"
	}
}

// buildReplay turns the raw event stream into a compact playback: high-level
// counts plus events bucketed into human groups. ENV_DENY events are collapsed
// into a single summary (count + keys) instead of one card each.
func buildReplay(evs []events.Event) (replaySummary, []replayGroup) {
	var sum replaySummary
	buckets := map[string][]timelineStep{}
	idx := 0
	for _, e := range evs {
		if e.Type == "ENV_DENY" {
			sum.EnvExcluded++
			if k, ok := e.Meta["key"].(string); ok {
				sum.EnvKeys = append(sum.EnvKeys, k)
			}
			continue
		}
		idx++
		step := timelineStep{
			Index:   idx,
			TS:      e.TS.UTC().Format(time.RFC3339),
			Label:   eventLabel(e),
			Status:  eventStatus(e),
			Path:    e.Path,
			Summary: eventSummary(e),
			Diff:    e.Diff,
			Detail:  eventDetail(e),
		}
		g := replayGroupOf(e.Type)
		buckets[g] = append(buckets[g], step)
		switch g {
		case "Setup & sandbox":
			sum.Setup++
		case "File changes":
			sum.AllowedChanges++
		case "Denials & reverts":
			sum.DeniedReverted++
		case "Evidence & finish":
			sum.EvidenceArtifacts++
		case "Review / rollback":
			if e.Type == "ROLLBACK" {
				sum.RollbackEvents++
			}
		}
		if e.Type == "RUN_FAILED" {
			sum.BlockedCommands++
		}
	}
	var groups []replayGroup
	for _, name := range replayGroupOrder {
		if steps := buckets[name]; len(steps) > 0 {
			groups = append(groups, replayGroup{Name: name, Steps: steps})
		}
	}
	return sum, groups
}

// ---- live run state (for viewer auto-update polling) ----------------------

type runState struct {
	RunID        string `json:"run_id"`
	Review       string `json:"review"`
	Verify       string `json:"verify"`
	Signed       bool   `json:"signed"`
	Rollback     bool   `json:"rollback"`
	RollbackMode string `json:"rollback_mode,omitempty"`
	Export       bool   `json:"export"`
	Updated      string `json:"updated"`
	Fingerprint  string `json:"fingerprint"`
}

func hasExportBundle(runDir string) bool {
	matches, _ := filepath.Glob(filepath.Join(runDir, "airlock-run-*.zip"))
	return len(matches) > 0
}

// computeRunState reads the small set of artifacts whose change should refresh
// the viewer, and produces a fingerprint that changes whenever review, verify,
// rollback, export, or digest/report state changes.
func computeRunState(a runmeta.Artifacts) runState {
	st := runState{RunID: a.RunID}
	rev, _ := review.Load(a.RunDir)
	st.Review = string(rev.State)
	if st.Review == "" {
		st.Review = "unreviewed"
	}
	if vr, err := runmeta.VerifyRun(a.RunID, a.Manifest); err == nil {
		st.Verify = vr.Status
	}
	st.Signed = a.Manifest.Digest.Signed
	if b, err := os.ReadFile(filepath.Join(a.RunDir, "rollback.json")); err == nil {
		st.Rollback = true
		var rr struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(b, &rr) == nil {
			st.RollbackMode = rr.Mode
		}
	}
	st.Export = a.Manifest.Export.Path != "" || hasExportBundle(a.RunDir)

	var maxT time.Time
	for _, name := range []string{"run_manifest.json", "review.json", "rollback.json", "run_digest.json", "run_digest.sig", filepath.Join("report", "index.html")} {
		if fi, err := os.Stat(filepath.Join(a.RunDir, name)); err == nil && fi.ModTime().After(maxT) {
			maxT = fi.ModTime()
		}
	}
	if !maxT.IsZero() {
		st.Updated = maxT.UTC().Format(time.RFC3339)
	}
	st.Fingerprint = fmt.Sprintf("%s|%s|%v|%s|%v|%v|%s",
		st.Review, st.Verify, st.Rollback, st.RollbackMode, st.Export, st.Signed, st.Updated)
	return st
}

func parseReviewRequest(r *http.Request) (review.Record, error) {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var rec review.Record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			return review.Record{}, err
		}
		return rec, nil
	}
	if err := r.ParseForm(); err != nil {
		return review.Record{}, err
	}
	return review.Record{
		State:    review.State(r.FormValue("state")),
		Note:     r.FormValue("note"),
		Reviewer: r.FormValue("reviewer"),
	}, nil
}

type patchInfo struct {
	Files   []string
	Summary string
}

func derivePatchSummary(evs []events.Event) patchInfo {
	set := map[string]struct{}{}
	diffCount := 0
	for _, e := range evs {
		if e.Path != "" && (strings.HasPrefix(e.Type, "FILE_") || e.Type == "POLICY_DENY") {
			set[e.Path] = struct{}{}
		}
		if e.Diff != "" {
			diffCount++
		}
	}
	files := make([]string, 0, len(set))
	for p := range set {
		files = append(files, p)
	}
	sort.Strings(files)
	s := fmt.Sprintf("%d files with %d diff event(s)", len(files), diffCount)
	if len(files) == 0 {
		s = "No patchable file changes in this run"
	}
	return patchInfo{Files: files, Summary: s}
}

func deriveTimelineSteps(evs []events.Event) []timelineStep {
	steps := make([]timelineStep, 0, len(evs))
	for i, e := range evs {
		steps = append(steps, timelineStep{
			Index:   i + 1,
			TS:      e.TS.UTC().Format(time.RFC3339),
			Label:   eventLabel(e),
			Status:  eventStatus(e),
			Path:    e.Path,
			Summary: eventSummary(e),
			Diff:    e.Diff,
			Detail:  eventDetail(e),
		})
	}
	return steps
}

func eventLabel(e events.Event) string {
	switch e.Type {
	case "RUN_START":
		return "Started task"
	case "CMD":
		return "Prepared adapter command"
	case "CHECKPOINT_CREATED":
		return "Created checkpoint"
	case "FILE_CREATE":
		return "Created file"
	case "FILE_WRITE":
		return "Modified file"
	case "FILE_REMOVE":
		return "Removed file"
	case "POLICY_DENY":
		return "Attempt blocked by policy"
	case "PATCH_READY":
		return "Generated patch"
	case "REVIEW_UPDATED":
		return "Review updated"
	case "ROLLBACK":
		return "Restored checkpoint"
	case "RUN_END":
		return "Run finished"
	case "RUN_FAILED":
		return "Run failed"
	default:
		return strings.ReplaceAll(strings.ToLower(e.Type), "_", " ")
	}
}

func eventStatus(e events.Event) string {
	switch e.Type {
	case "ROLLBACK":
		return "rollback"
	case "ENV_DENY", "NET_DENY", "NET_ALLOW", "SANDBOX_NETWORK", "SANDBOX_NETWORK_UNSUPPORTED":
		// Environment/network guardrails are informational, not violations.
		// Reserve red styling for real policy denials and failures.
		return "info"
	}
	if e.Type == "POLICY_DENY" || e.Type == "PATH_DENY" || e.Type == "SECRET_DENY" ||
		strings.Contains(e.Type, "ERROR") || strings.Contains(e.Type, "FAILED") {
		return "blocked"
	}
	if strings.HasPrefix(e.Type, "FILE_") {
		return "changed"
	}
	return "allowed"
}

func eventSummary(e events.Event) string {
	if e.Summary != "" {
		return e.Summary
	}
	if e.Path != "" {
		return e.Path
	}
	return e.Type
}

func eventDetail(e events.Event) string {
	if len(e.Meta) == 0 && len(e.Policy) == 0 {
		return ""
	}
	b, _ := json.MarshalIndent(map[string]any{"meta": e.Meta, "policy": e.Policy, "risk": e.Risk, "approval": e.Approval}, "", "  ")
	return string(b)
}

func deriveRunCard(a runmeta.Artifacts) runCard {
	adapter := a.Manifest.Adapter.Name
	if adapter == "" {
		adapter = "unknown-adapter"
	}

	cmd, _ := extractCommandTask(a.Events)

	// Detect whether the command was blocked before execution (policy-blocked run).
	isBlocked := false
	for _, e := range a.Events {
		if e.Type == "RUN_FAILED" {
			if class, ok := e.Meta["class"].(string); ok && class == "policy" {
				isBlocked = true
			}
		}
	}
	if a.Manifest.Status.Terminal == "failed" && a.Manifest.ApprovalSummary.DeniedCount > 0 {
		isBlocked = true
	}

	hasChanges := len(a.Manifest.TouchedPaths) > 0
	title := classifyDisplayCategory(adapter, cmd, hasChanges, isBlocked)

	outcome, outcomeClass := deriveOutcome(a.Manifest)
	verifyState := "unverified"
	if vr, err := runmeta.VerifyRun(a.RunID, a.Manifest); err == nil {
		verifyState = vr.Status
	}
	r := review.Record{State: review.StateUnreviewed}
	if rev, err := review.Load(a.RunDir); err == nil {
		r = rev
	}
	changed, blocked := changedAndBlockedCounts(a.Events, a.Manifest)
	riskSummary := "Low risk"
	if a.Manifest.RiskSummary.HighCount > 0 {
		riskSummary = fmt.Sprintf("High risk %d", a.Manifest.RiskSummary.HighCount)
	} else if a.Manifest.RiskSummary.MediumCount > 0 {
		riskSummary = fmt.Sprintf("Medium risk %d", a.Manifest.RiskSummary.MediumCount)
	}
	when := ""
	if len(a.Events) > 0 {
		when = a.Events[0].TS.Local().Format("2006-01-02 15:04")
	}
	target := a.Manifest.Execution.Target
	if target == "" {
		target = "local"
	}

	// Build operator-facing subtitle: observable counts + verify state.
	var subtitleParts []string
	if changed > 0 {
		subtitleParts = append(subtitleParts, fmt.Sprintf("%d write(s) allowed", changed))
	}
	policyDenyCount := 0
	for _, e := range a.Events {
		if e.Type == "POLICY_DENY" {
			policyDenyCount++
		}
	}
	if isBlocked {
		subtitleParts = append(subtitleParts, "command blocked before execution")
	} else if policyDenyCount > 0 {
		subtitleParts = append(subtitleParts, fmt.Sprintf("%d denied/reverted", policyDenyCount))
	}
	subtitleParts = append(subtitleParts, verifyState)
	subtitle := strings.Join(subtitleParts, " · ")

	// Truncate command for card display.
	displayCmd := cmd
	if len(displayCmd) > 90 {
		displayCmd = displayCmd[:87] + "..."
	}

	return runCard{
		RunID:         a.RunID,
		Title:         title,
		Subtitle:      subtitle,
		Command:       displayCmd,
		Outcome:       outcome,
		OutcomeClass:  outcomeClass,
		Adapter:       adapter,
		When:          when,
		RiskSummary:   riskSummary,
		FilesChanged:  changed,
		Blocked:       blocked,
		ReviewState:   string(r.State),
		VerifyState:   verifyState,
		Signed:        a.Manifest.Digest.Signed,
		HasRollback:   runmeta.Exists(filepath.Join(a.RunDir, "rollback.json")),
		Target:        target,
		Mode:          a.Manifest.ExecutionMode,
		Sandbox:       a.Manifest.Sandbox.Mode,
		PolicyPack:    a.Manifest.PolicyPack.Name,
		DenyRuleCount: len(a.Manifest.PolicySummary.DenyWrite),
		ReplayURL:     "/runs/" + a.RunID + "#timeline",
		RunURL:        "/runs/" + a.RunID,
		ExportCmd:     "./airlock export " + a.RunID + " --format zip",
		RollbackCmd:   "./airlock rollback " + a.RunID + " --checkpoint cp-0",
	}
}

func extractCommandTask(evs []events.Event) (string, string) {
	for _, e := range evs {
		if e.Type != "CMD" {
			continue
		}
		cmd, _ := e.Meta["cmd"].(string)
		task, _ := e.Meta["task"].(string)
		return strings.TrimSpace(cmd), strings.TrimSpace(task)
	}
	return "", ""
}

// classifyDisplayCategory derives the operator-facing action label for a run.
// Based solely on observable facts from manifest and events — no invented semantics.
func classifyDisplayCategory(adapter, command string, hasChanges, isBlocked bool) string {
	if adapter == "sentinel" {
		return "Sentinel Session"
	}
	if isBlocked {
		return "Blocked Shell Operation"
	}
	if strings.Contains(command, "byom-agent") {
		return "BYOM Agent Run"
	}
	if hasChanges {
		return "Workspace Mutation"
	}
	return "Policy-Governed Run"
}

func deriveOutcome(m runmeta.RunManifest) (string, string) {
	if m.Status.Terminal == "failed" {
		return "Failed", "bad"
	}
	blocked := len(m.DeniedPaths) + m.ApprovalSummary.DeniedCount
	if blocked > 0 {
		return "Blocked actions handled", "warn"
	}
	if m.Status.Terminal == "success" || m.Status.Terminal == "" {
		return "Success", "ok"
	}
	return strings.Title(m.Status.Terminal), "mutedb"
}

func changedAndBlockedCounts(evs []events.Event, m runmeta.RunManifest) (int, int) {
	changedSet := map[string]struct{}{}
	blocked := 0
	for _, e := range evs {
		if strings.HasPrefix(e.Type, "FILE_") && e.Path != "" {
			changedSet[e.Path] = struct{}{}
		}
		if e.Type == "POLICY_DENY" {
			blocked++
		}
	}
	if blocked == 0 {
		blocked = len(m.DeniedPaths)
		if m.ApprovalSummary.DeniedCount > blocked {
			blocked = m.ApprovalSummary.DeniedCount
		}
	}
	return len(changedSet), blocked
}

func loadIndex() index.Store {
	store, err := index.Load(index.DefaultPath())
	if err != nil {
		store, _ = index.Rebuild(".airlock/runs")
		_ = index.Save(index.DefaultPath(), store)
	}
	sort.Slice(store.Runs, func(i, j int) bool { return store.Runs[i].Timestamp > store.Runs[j].Timestamp })
	return store
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func open(path string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", path).Run()
	case "windows":
		return exec.Command("cmd", "/C", "start", path).Run()
	default:
		return exec.Command("xdg-open", path).Run()
	}
}

func osReadFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, limit)
	n, err := f.Read(b)
	if err != nil && err.Error() != "EOF" {
		return nil, err
	}
	return b[:n], nil
}

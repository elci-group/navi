use crate::common::*;
use crate::svg;
use realm_core::{wire, EvidenceNode, Realm};
use realm_layout::Layout;
use serde_json::{json, Value};

fn tree(n: &EvidenceNode) -> Value {
    json!({
        "id": n.id, "kind": n.kind, "summary": n.summary,
        "children": n.children.iter().map(tree).collect::<Vec<_>>(),
    })
}

fn data(realm: &Realm, layout: &Layout) -> Value {
    let pt = |id: &str| svg::anchor(layout, id).map(|(x, y)| json!([x, y]));
    let agents: Vec<Value> = realm
        .agents
        .iter()
        .map(|a| {
            let home = a.location.as_deref().and_then(pt);
            let waypoints: Vec<Value> = a
                .trajectory
                .iter()
                .map(|w| {
                    let mut path: Vec<Value> = vec![];
                    if let Some(first) = w.route.first() {
                        path.extend(pt(&first.from));
                    }
                    path.extend(w.route.iter().filter_map(|s| pt(&s.to)));
                    json!({
                        "seq": w.seq,
                        "at": w.at.to_string(),
                        "phase": wire(&w.phase),
                        "where": w.location.as_deref().map(|l| name(realm, l)),
                        "anchor": w.location.as_deref().and_then(pt),
                        "path": path,
                        "steps": w.route.iter().map(|s| step_label(realm, s)).collect::<Vec<_>>(),
                        "brief": brief_lines(realm, w),
                    })
                })
                .collect();
            json!({ "id": a.realm_id, "name": a.name, "home": home, "hud": hud_lines(realm, a), "waypoints": waypoints })
        })
        .collect();
    let evidence: serde_json::Map<String, Value> = realm
        .evidence
        .iter()
        .map(|e| (e.realm_id.clone(), tree(&e.tree)))
        .collect();
    let names: serde_json::Map<String, Value> = realm
        .entities
        .iter()
        .map(|e| (e.realm_id.clone(), json!(e.name)))
        .chain(realm.edges.iter().map(|e| {
            (
                e.realm_id.clone(),
                json!(format!(
                    "{} {} → {}",
                    wire(&e.semantic_type),
                    name(realm, &e.from),
                    name(realm, &e.to)
                )),
            )
        }))
        .chain(realm.controls.iter().map(|c| {
            (
                c.realm_id.clone(),
                json!(format!("{} {}", wire(&c.semantic_type), c.name)),
            )
        }))
        .chain(
            realm
                .hazards
                .iter()
                .map(|h| (h.realm_id.clone(), json!(h.visual_contract.label))),
        )
        .collect();
    json!({ "agents": agents, "evidence": evidence, "names": names })
}

pub fn render(realm: &Realm, layout: &Layout) -> String {
    let svg = svg::render(realm, layout, None);
    // Escape markup-significant characters as JSON unicode escapes, so no
    // string in the data can close or open an element inside <script>.
    let data = data(realm, layout)
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    let title = format!(
        "Realm · {}",
        realm
            .source_digest
            .get(..19)
            .unwrap_or(&realm.source_digest)
    );
    TEMPLATE
        .replace("{{TITLE}}", &title)
        .replace("{{SVG}}", &svg)
        .replace("{{DATA}}", &data)
        .replace("{{TOP}}", &svg::TOP.to_string())
        .replace("{{BANNER}}", &banner_html(realm))
}

const TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
  :root { color-scheme: dark; --bg:#101418; --panel:#161b22; --line:#2b323b; --fg:#c9d1d9; --dim:#8a8f98; --navi:#14a6d9; --warn:#e0a030; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:13px/1.45 ui-monospace, Menlo, Consolas, monospace; }
  header { display:flex; gap:12px; align-items:center; padding:10px 16px; border-bottom:1px solid var(--line); flex-wrap:wrap; }
  header b { color:var(--navi); }
  button { background:var(--panel); color:var(--fg); border:1px solid var(--line); border-radius:6px; padding:4px 10px; font:inherit; cursor:pointer; }
  button:hover { border-color:var(--navi); }
  input[type=range] { width:min(360px, 60vw); accent-color:var(--navi); }
  main { display:grid; grid-template-columns: minmax(0,1fr) 460px; min-height:calc(100vh - 50px); }
  #map { overflow:auto; border-right:1px solid var(--line); }
  #map svg [data-realm-id]:not([data-realm-id="realm:universe"]) { cursor:pointer; }
  #map svg .selected rect, #map svg .selected path, #map svg .selected circle { filter: drop-shadow(0 0 4px #fff); }
  aside { padding:12px 16px; overflow:auto; }
  h2 { font-size:12px; color:var(--dim); text-transform:uppercase; letter-spacing:.08em; margin:14px 0 6px; }
  pre { margin:0; white-space:pre-wrap; }
  #brief .warn { color:var(--warn); }
  ul.tree { list-style:none; margin:0; padding-left:14px; border-left:1px dotted var(--line); }
  ul.tree.root { padding-left:0; border:0; }
  .k { color:var(--navi); } .id { color:var(--dim); }
  .k.observation { color:#2f8f5b; } .k.hypothesis { color:#8e5cc8; } .k.derived { color:#c98a1b; }
  @media (max-width: 900px) { main { grid-template-columns: 1fr; } #map { border-right:0; border-bottom:1px solid var(--line); } }
</style>
</head>
<body>
{{BANNER}}<header>
  <b>NAVI TIMELINE</b>
  <button id="prev" title="previous event">◀</button>
  <button id="play" title="play">▶ play</button>
  <button id="next" title="next event">▶</button>
  <input id="t" type="range" min="0" value="0">
  <span id="tlabel"></span>
</header>
<main>
  <div id="map">{{SVG}}</div>
  <aside>
    <h2>Navi at this event</h2>
    <pre id="brief"></pre>
    <h2>Movement</h2>
    <pre id="moves"></pre>
    <h2 id="seltitle">Selection — click anything in the realm</h2>
    <div id="sel"></div>
  </aside>
</main>
<script>
// Display only: every value below was computed and validated by the realm
// compiler. This script interpolates Navi's movement along precomputed
// routes and looks things up; it makes no security decisions.
const DATA = {{DATA}};
const agent = DATA.agents[0];
const $ = (id) => document.getElementById(id);
const navi = agent && document.querySelector(`[data-realm-id="${agent.id}"]`);
let idx = agent ? agent.waypoints.length - 1 : 0, playing = null, anim = null, arrive = null;

function setText(el, lines) {
  el.textContent = "";
  for (const l of lines) {
    const span = document.createElement("span");
    span.textContent = l + "\n";
    if (/HUMAN APPROVAL|awaiting/.test(l)) span.className = "warn";
    el.appendChild(span);
  }
}

function place(p) {
  if (!navi || !p || !agent.home) return;
  navi.setAttribute("transform", `translate(${p[0] - agent.home[0]},${p[1] - agent.home[1]})`);
}

function move(path, done) {
  cancelAnimationFrame(anim); clearTimeout(arrive);
  if (!path || path.length < 2) { done(); return; }
  const per = 380, t0 = performance.now();
  // Arrival is guaranteed by a timer, not by the animation: frames may never
  // run (background tab, headless), and semantic state must still update.
  let finished = false;
  const finish = () => { if (finished) return; finished = true; cancelAnimationFrame(anim); clearTimeout(arrive); done(); };
  arrive = setTimeout(finish, per * (path.length - 1) + 30);
  const tick = (now) => {
    if (finished) return;
    const k = Math.min((now - t0) / per, path.length - 1);
    const i = Math.min(Math.floor(k), path.length - 2), f = k - i;
    const a = path[i], b = path[i + 1];
    place([a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f]);
    if (k < path.length - 1) anim = requestAnimationFrame(tick); else finish();
  };
  anim = requestAnimationFrame(tick);
}

function show(i, animate) {
  if (!agent) return;
  const w = agent.waypoints[i];
  const settle = () => {
    // Semantic state snaps at the waypoint; it is never interpolated.
    place(w.anchor);
    setText($("brief"), [`#${w.seq}  ${w.at}  ${w.phase}`].concat(w.brief));
  };
  setText($("moves"), w.steps.length ? w.steps : ["(attention did not move)"]);
  $("t").value = i;
  $("tlabel").textContent = `event ${i + 1} / ${agent.waypoints.length}`;
  if (animate) move(w.path, settle); else settle();
  idx = i;
}

function renderTree(n) {
  const li = document.createElement("li");
  const k = document.createElement("span"); k.className = "k " + n.kind; k.textContent = `[${n.kind}] `;
  const id = document.createElement("span"); id.className = "id"; id.textContent = n.id + "  ";
  const s = document.createElement("span"); s.textContent = n.summary;
  li.append(k, id, s);
  if (n.children && n.children.length) {
    const ul = document.createElement("ul"); ul.className = "tree";
    n.children.forEach(c => ul.appendChild(renderTree(c)));
    li.appendChild(ul);
  }
  return li;
}

function select(id, g) {
  document.querySelectorAll(".selected").forEach(e => e.classList.remove("selected"));
  if (g) g.classList.add("selected");
  const sel = $("sel"); sel.textContent = "";
  if (agent && id === agent.id) {
    $("seltitle").textContent = "Selection — Navi";
    const pre = document.createElement("pre"); setText(pre, agent.hud); sel.appendChild(pre);
    return;
  }
  $("seltitle").textContent = "Selection — " + (DATA.names[id] || id);
  const t = DATA.evidence[id];
  if (!t) { sel.textContent = "No evidence chain for this element."; return; }
  const ul = document.createElement("ul"); ul.className = "tree root";
  ul.appendChild(renderTree(t)); sel.appendChild(ul);
}

document.querySelectorAll("#map [data-realm-id]").forEach(g => {
  g.addEventListener("click", (ev) => { ev.stopPropagation(); select(g.dataset.realmId, g); });
});
if (agent) {
  $("t").max = agent.waypoints.length - 1;
  $("t").addEventListener("input", e => show(+e.target.value, false));
  $("prev").onclick = () => idx > 0 && show(idx - 1, false);
  $("next").onclick = () => idx < agent.waypoints.length - 1 && show(idx + 1, true);
  $("play").onclick = () => {
    if (playing) { clearInterval(playing); playing = null; $("play").textContent = "▶ play"; return; }
    $("play").textContent = "❚❚ pause";
    show(0, false);
    playing = setInterval(() => {
      if (idx >= agent.waypoints.length - 1) { clearInterval(playing); playing = null; $("play").textContent = "▶ play"; return; }
      show(idx + 1, true);
    }, 1400);
  };
  show(idx, false);
  select(agent.id, navi);
} else {
  setText($("brief"), ["No agents in this realm."]);
}
</script>
</body>
</html>
"##;

pub(crate) fn banner_html(realm: &Realm) -> String {
    realm.banner().map_or(String::new(), |b| {
        format!(
            r#"<div style="background:#3a2a08;color:#e0a030;border-bottom:2px dashed #e0a030;padding:8px 16px;font-weight:bold">{}</div>"#,
            b.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
        )
    })
}

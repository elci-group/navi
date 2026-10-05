//! The security DVR page (directive §15, §16): LIVE, PAUSE, STEP, REWIND,
//! REPLAY and COMPARE over pre-rendered frames. One layout (the incident's
//! final state) is used for every frame so places never jump around; a
//! place that does not exist yet is simply not drawn.

use crate::common::*;
use crate::{gate, svg, Refused};
use navi_ontology::Timestamp;
use realm_core::{wire, Realm};
use serde_json::{json, Map, Value};

/// One instant of a replay, as the renderer needs it.
pub struct DvrFrame<'a> {
    pub at: Timestamp,
    /// What happened at this instant (§16 lines).
    pub lines: &'a [String],
    pub realm: &'a Realm,
}

/// Per-object one-line state, used by COMPARE in the page.
fn summaries(r: &Realm) -> Map<String, Value> {
    let mut m = Map::new();
    for e in &r.entities {
        let hz = hazard_mark(e).map_or(String::new(), |h| format!(", {h}"));
        m.insert(
            e.realm_id.clone(),
            json!(format!(
                "{} — {}, trust {}{hz}",
                e.name,
                wire(&e.semantic_type),
                wire(&e.trust_state)
            )),
        );
    }
    for e in &r.edges {
        m.insert(
            e.realm_id.clone(),
            json!(format!(
                "{} {} → {}",
                wire(&e.semantic_type),
                name(r, &e.from),
                name(r, &e.to)
            )),
        );
    }
    for c in &r.controls {
        m.insert(
            c.realm_id.clone(),
            json!(format!(
                "{} {} ({})",
                wire(&c.semantic_type),
                c.name,
                wire(&c.status)
            )),
        );
    }
    for h in &r.hazards {
        let actor = h.actor.as_deref().map_or("?", |a| name(r, a));
        m.insert(
            h.realm_id.clone(),
            json!(format!(
                "{} — {}, actor {actor}",
                h.visual_contract.label,
                wire(&h.view)
            )),
        );
    }
    for a in &r.agents {
        let at = a.location.as_deref().map_or("?", |l| name(r, l));
        let acts: Vec<String> = a
            .actions
            .iter()
            .map(|x| {
                format!(
                    "{} {}",
                    x.realm_id.trim_start_matches("realm:"),
                    wire(&x.state)
                )
            })
            .collect();
        m.insert(
            a.realm_id.clone(),
            json!(format!(
                "{} {} @ {at}{}",
                a.name,
                a.phase.map_or("idle".into(), |p| wire(&p)),
                if acts.is_empty() {
                    String::new()
                } else {
                    format!("; {}", acts.join(", "))
                }
            )),
        );
    }
    m
}

pub fn render(frames: &[DvrFrame]) -> Result<String, Refused> {
    let Some(last) = frames.last() else {
        return Err(Refused(vec![]));
    };
    for f in frames {
        gate(f.realm)?;
    }
    let layout = realm_layout::layout(last.realm);
    let data: Vec<Value> = frames
        .iter()
        .map(|f| {
            json!({
                "at": f.at.to_string(),
                "lines": f.lines,
                "svg": svg::render(f.realm, &layout, None),
                "state": summaries(f.realm),
            })
        })
        .collect();
    let data = Value::Array(data)
        .to_string()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    Ok(TEMPLATE
        .replace("{{BANNER}}", &crate::html::banner_html(last.realm))
        .replace(
            "{{TITLE}}",
            &format!("Security DVR · {} frames", frames.len()),
        )
        .replace("{{DATA}}", &data))
}

const TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
  :root { color-scheme: dark; --bg:#101418; --panel:#161b22; --line:#2b323b; --fg:#c9d1d9; --dim:#8a8f98; --navi:#14a6d9; --warn:#e0a030; --add:#2f8f5b; --del:#c0392b; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:13px/1.45 ui-monospace, Menlo, Consolas, monospace; }
  header { display:flex; gap:8px; align-items:center; padding:10px 16px; border-bottom:1px solid var(--line); flex-wrap:wrap; }
  header b { color:var(--navi); margin-right:6px; }
  button { background:var(--panel); color:var(--fg); border:1px solid var(--line); border-radius:6px; padding:4px 10px; font:inherit; cursor:pointer; }
  button:hover { border-color:var(--navi); }
  button.on { border-color:var(--navi); color:var(--navi); }
  input[type=range] { width:min(320px, 50vw); accent-color:var(--navi); }
  main { display:grid; grid-template-columns:minmax(0,1fr) 480px; min-height:calc(100vh - 50px); }
  #map { overflow:auto; border-right:1px solid var(--line); }
  aside { padding:12px 16px; overflow:auto; max-height:calc(100vh - 50px); }
  h2 { font-size:12px; color:var(--dim); text-transform:uppercase; letter-spacing:.08em; margin:14px 0 6px; }
  ol { list-style:none; margin:0; padding:0; }
  #log li { padding:1px 4px; border-radius:4px; cursor:pointer; color:var(--dim); }
  #log li.past { color:var(--fg); }
  #log li.now { background:#14a6d922; color:#fff; }
  #diff li.added { color:var(--add); } #diff li.removed { color:var(--del); } #diff li.changed { color:var(--warn); }
  @media (max-width: 900px) { main { grid-template-columns:1fr; } #map { border-right:0; border-bottom:1px solid var(--line); } aside { max-height:none; } }
</style>
</head>
<body>
{{BANNER}}<header>
  <b>SECURITY DVR</b>
  <button id="replay" title="replay from the start">⏮ replay</button>
  <button id="rewind" title="step back">◀ rewind</button>
  <button id="play" title="play / pause">⏵ play</button>
  <button id="step" title="step forward">step ▶</button>
  <button id="live" title="jump to the latest state">● live</button>
  <input id="t" type="range" min="0" value="0">
  <span id="tlabel"></span>
  <button id="mark" title="compare: mark this instant as A">compare: mark A</button>
</header>
<main>
  <div id="map"></div>
  <aside>
    <h2>At this instant</h2>
    <ol id="now"></ol>
    <h2 id="cmptitle">Compare — mark an instant as A, then move</h2>
    <ol id="diff"></ol>
    <h2>Incident log</h2>
    <ol id="log"></ol>
  </aside>
</main>
<script>
// Display only: frames, event lines and state summaries were computed and
// validated before this page was written. Nothing here is inferred.
const F = {{DATA}};
const $ = (id) => document.getElementById(id);
let i = F.length - 1, timer = null, markA = null;

function li(text, cls) { const e = document.createElement("li"); e.textContent = text; if (cls) e.className = cls; return e; }

function diff() {
  const out = $("diff"); out.textContent = "";
  if (markA === null) return;
  $("cmptitle").textContent = `Compare — A = ${F[markA].at}  ·  B = ${F[i].at}`;
  const a = F[markA].state, b = F[i].state; let n = 0;
  for (const k of Object.keys(b)) {
    if (!(k in a)) { out.appendChild(li(`+ ${b[k]}`, "added")); n++; }
    else if (a[k] !== b[k]) { out.appendChild(li(`~ ${a[k]}\n  → ${b[k]}`, "changed")); n++; }
  }
  for (const k of Object.keys(a)) if (!(k in b)) { out.appendChild(li(`− ${a[k]}`, "removed")); n++; }
  if (!n) out.appendChild(li("no differences"));
}

function show(k) {
  i = Math.max(0, Math.min(F.length - 1, k));
  $("map").innerHTML = F[i].svg;
  $("t").value = i;
  $("tlabel").textContent = `${F[i].at}  ·  frame ${i + 1}/${F.length}`;
  $("live").classList.toggle("on", i === F.length - 1);
  const now = $("now"); now.textContent = "";
  F[i].lines.forEach(l => now.appendChild(li(l)));
  [...$("log").children].forEach(e => {
    const f = +e.dataset.frame;
    e.className = f < i ? "past" : f === i ? "now" : "";
  });
  diff();
}

function stop() { clearInterval(timer); timer = null; $("play").textContent = "⏵ play"; $("play").classList.remove("on"); }
function play() {
  if (timer) { stop(); return; }
  if (i >= F.length - 1) show(0);
  $("play").textContent = "⏸ pause"; $("play").classList.add("on");
  timer = setInterval(() => { if (i >= F.length - 1) stop(); else show(i + 1); }, 1100);
}

F.forEach((f, k) => f.lines.forEach(l => {
  const e = li(`${f.at}  ${l}`); e.dataset.frame = k; e.onclick = () => { stop(); show(k); }; $("log").appendChild(e);
}));
$("t").max = F.length - 1;
$("t").addEventListener("input", e => { stop(); show(+e.target.value); });
$("replay").onclick = () => { stop(); show(0); play(); };
$("rewind").onclick = () => { stop(); show(i - 1); };
$("step").onclick = () => { stop(); show(i + 1); };
$("play").onclick = play;
$("live").onclick = () => { stop(); show(F.length - 1); };
$("mark").onclick = () => { markA = i; $("mark").textContent = `compare: A = ${F[i].at}`; diff(); };
show(i);
</script>
</body>
</html>
"##;

"""Read-only local dashboard for sanitized CRUCIBLE episode evidence.

Run with ``python -m crucible.dashboard --db data/experience.db``. The server
never writes episodes or accepts mutations; it reads the ExperienceBank API.
Bind to loopback by default. Put authentication/TLS in front of it before
exposing it beyond a trusted host.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import parse_qs, urlsplit

from crucible.experience import ExperienceBank
from crucible.plugins.d6_output_filter import OutputFilterPlugin
from crucible.scenarios import CANARY
from crucible.trajectory import TrajectoryStore


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CRUCIBLE · Containment evidence</title>
  <style nonce="__NONCE__">
    :root { color-scheme: dark; font: 15px/1.5 system-ui, -apple-system, sans-serif; background: #101820; color: #ecf2f2; }
    * { box-sizing: border-box; }
    body { max-width: 1180px; margin: 0 auto; padding: 28px 22px 60px; }
    header { display: flex; align-items: end; justify-content: space-between; gap: 20px; flex-wrap: wrap; margin-bottom: 28px; }
    h1, h2, p { margin: 0; }
    h1 { font-size: 2rem; letter-spacing: -.035em; line-height: 1.1; }
    h2 { font-size: 1rem; letter-spacing: .02em; margin-bottom: 14px; }
    .eyebrow { color: #6fe5b3; font-size: .74rem; font-weight: 750; letter-spacing: .15em; text-transform: uppercase; margin-bottom: 9px; }
    .subtle { color: #a8b9bd; font-size: .88rem; margin-top: 9px; }
    .meta { color: #a8b9bd; font-size: .82rem; text-align: right; }
    button { border: 1px solid #52727a; border-radius: 7px; background: #1e343d; color: #ecf2f2; padding: 8px 13px; font: inherit; cursor: pointer; margin-top: 8px; }
    button:hover { background: #294750; }
    .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 12px; }
    .card { background: #19262e; border: 1px solid #2b414b; border-radius: 11px; padding: 17px 19px; }
    .label { color: #a8b9bd; font-size: .75rem; letter-spacing: .06em; text-transform: uppercase; }
    .value { display: block; font-size: 1.8rem; font-weight: 750; margin-top: 4px; font-variant-numeric: tabular-nums; }
    .danger { color: #ff908a; }
    .safe { color: #6fe5b3; }
    .chart-card { margin-bottom: 12px; }
    .legend { display: flex; gap: 22px; flex-wrap: wrap; color: #bfd0d0; font-size: .82rem; margin-bottom: 8px; }
    .swatch { display: inline-block; width: 13px; height: 3px; vertical-align: middle; margin-right: 7px; }
    .swatch.attack { background: #ff908a; }
    .swatch.safe { background: #6fe5b3; }
    .chart { width: 100%; height: auto; min-height: 210px; display: block; }
    .grid { stroke: #314650; stroke-width: 1; }
    .axis-label { fill: #95aeb2; font-size: 11px; }
    .panel-grid { display: grid; grid-template-columns: minmax(0, 1.7fr) minmax(270px, 1fr); gap: 12px; }
    .table-wrap { max-height: 520px; overflow: auto; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: .84rem; }
    th { position: sticky; top: 0; background: #19262e; color: #a8b9bd; font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; }
    td, th { padding: 9px 8px; border-bottom: 1px solid #30434b; vertical-align: top; }
    td:nth-child(2) { max-width: 300px; overflow-wrap: anywhere; }
    .pill { display: inline-block; padding: 2px 7px; border-radius: 5px; font-size: .72rem; font-weight: 750; text-transform: uppercase; }
    .pill.deny { background: #5b292e; color: #ffbbb4; }
    .pill.allow { background: #1f4a3a; color: #a4f2c9; }
    .pill.other { background: #344850; color: #d3e0e1; }
    .pattern { padding: 11px 0; border-bottom: 1px solid #30434b; }
    .pattern:last-child { border-bottom: 0; }
    .pattern strong { display: block; font-size: .84rem; }
    .pattern small { display: block; color: #a8b9bd; margin-top: 3px; }
    .empty { color: #a8b9bd; padding: 16px 0; }
    .error { color: #ffbbb4; }
    /* PRIVATE_LIVE_START */
    body.trajectory-open { max-width: 1660px; }
    .dashboard-layout.trajectory-open { display: grid; grid-template-columns: minmax(0, 1fr) minmax(320px, 390px); gap: 16px; align-items: start; }
    .dashboard-layout > main { min-width: 0; }
    .trajectory-actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; }
    .trajectory-pane { position: sticky; top: 14px; height: calc(100vh - 28px); min-height: 440px; overflow: hidden; display: flex; flex-direction: column; background: #172831; border: 1px solid #42606a; border-radius: 11px; }
    .trajectory-pane[hidden] { display: none; }
    .trajectory-head { display: flex; gap: 10px; justify-content: space-between; align-items: start; padding: 17px 18px 12px; border-bottom: 1px solid #304750; }
    .trajectory-head h2 { font-size: 1.12rem; margin: 0; }
    .trajectory-head button { margin: 0; padding: 4px 9px; }
    .trajectory-summary { padding: 12px 18px; border-bottom: 1px solid #304750; }
    .trajectory-summary strong { display: block; font-size: .86rem; overflow-wrap: anywhere; }
    .trajectory-summary .subtle { margin-top: 3px; }
    .trajectory-scroll { overflow-y: auto; overscroll-behavior: contain; padding: 8px 18px 24px; flex: 1; }
    .trajectory-list { list-style: none; margin: 0; padding: 0 0 0 13px; border-left: 1px solid #47636b; }
    .trajectory-event { position: relative; margin: 0 0 15px 14px; padding: 0 0 0 1px; overflow-wrap: anywhere; }
    .trajectory-event::before { content: ''; position: absolute; width: 8px; height: 8px; border-radius: 50%; background: #83b1ba; left: -19px; top: 7px; }
    .trajectory-event.deny::before, .trajectory-event.error::before { background: #ff908a; }
    .trajectory-event.allow::before, .trajectory-event.complete::before { background: #6fe5b3; }
    .trajectory-event-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
    .trajectory-phase { font-size: .88rem; font-weight: 700; }
    .trajectory-time { color: #9fb4b9; font-size: .73rem; white-space: nowrap; font-variant-numeric: tabular-nums; }
    .trajectory-meta { color: #a8b9bd; font-size: .75rem; margin-top: 2px; }
    .trajectory-detail { color: #dce8e9; font-size: .83rem; white-space: pre-wrap; margin-top: 5px; }
    .trajectory-empty { color: #a8b9bd; padding-top: 12px; font-size: .86rem; }
    @media (max-width: 950px) {
      .dashboard-layout.trajectory-open { display: block; }
      .trajectory-pane { position: fixed; z-index: 10; left: 8px; right: 8px; bottom: 8px; top: auto; height: min(70vh, 720px); min-height: 300px; box-shadow: 0 0 0 100vmax #08121999; }
      .trajectory-actions { justify-content: flex-start; }
    }
    /* PRIVATE_LIVE_END */
    @media (max-width: 760px) { .stats, .panel-grid { grid-template-columns: 1fr; } .meta { text-align: left; } }
  </style>
</head>
<body>
  <div class="dashboard-layout" id="dashboard-layout"><main>
  <header>
    <div><p class="eyebrow">CRUCIBLE / evidence readout</p><h1>Containment under pressure</h1>
      <p class="subtle">Recorded episodes only. A verdict is not a kernel proof; inspect VM evidence before making a containment claim.</p></div>
    <div class="meta"><span id="updated">Waiting for records</span><br><button id="refresh" type="button">Refresh</button>
      <!-- PRIVATE_LIVE_START -->
      <div class="trajectory-actions"><button id="show-trajectory" type="button" aria-controls="trajectory-pane" aria-expanded="false">Show trajectory</button></div>
      <!-- PRIVATE_LIVE_END -->
    </div>
  </header>
  <section class="stats" aria-label="Episode summary">
    <div class="card"><span class="label">Episodes</span><span class="value" id="total">0</span></div>
    <div class="card"><span class="label">Attack success · container runs</span><span class="value danger" id="attack-rate">—</span></div>
    <div class="card"><span class="label">Contained + task complete · model runs</span><span class="value safe" id="safe-rate">—</span></div>
    <div class="card"><span class="label">Task complete · simulation</span><span class="value" id="fixture-rate">—</span></div>
  </section>
  <section class="card chart-card"><h2>Outcome across recorded episodes</h2>
    <div class="legend"><span><i class="swatch attack"></i>Attack success, cumulative live worker runs</span>
      <span><i class="swatch safe"></i>Contained + task complete, among model runs</span></div>
    <svg class="chart" id="chart" viewBox="0 0 720 240" role="img" aria-label="Cumulative episode outcome rates"></svg>
    <p class="subtle" id="evidence-note">Only container-backed VM episodes appear in these curves. Simulation completion is reported separately.</p>
  </section>
  <section class="card chart-card"><h2>Latest delivered report</h2>
    <p id="latest-report" class="empty">No completed report recorded yet.</p>
    <p id="latest-report-meta" class="subtle"></p>
  </section>
  <div class="panel-grid">
    <section class="card"><h2>Action and verdict log</h2><div class="table-wrap"><table>
      <thead><tr><th>Round</th><th>Action / result</th><th>Pre-exec verdict</th><th>Control</th></tr></thead><tbody id="events"></tbody>
    </table><p id="events-empty" class="empty">No actions recorded yet.</p></div></section>
    <section class="card"><h2>Attack / defense patterns</h2><div id="patterns"><p class="empty">No patterns recorded yet.</p></div></section>
  </div>
  </main>
  <!-- PRIVATE_LIVE_START -->
  <aside id="trajectory-pane" class="trajectory-pane" aria-labelledby="trajectory-title" hidden>
    <div class="trajectory-head"><div><p class="eyebrow">Live remote task</p><h2 id="trajectory-title">Agent trajectory</h2></div>
      <button id="close-trajectory" type="button" aria-label="Close agent trajectory">Close</button></div>
    <div class="trajectory-summary"><strong id="trajectory-task">Waiting for a task</strong>
      <p id="trajectory-state" class="subtle" role="status" aria-live="polite">Connect to observe the next remote run.</p></div>
    <div class="trajectory-scroll" id="trajectory-scroll"><ol id="trajectory-events" class="trajectory-list" aria-label="Remote task events"></ol>
      <p id="trajectory-empty" class="trajectory-empty">No task events yet.</p></div>
  </aside>
  <!-- PRIVATE_LIVE_END -->
  </div>
  <script nonce="__NONCE__">
    const $ = id => document.getElementById(id);
    const svgNS = 'http://www.w3.org/2000/svg';
    function node(name, text, className) {
      const el = document.createElement(name);
      if (text !== undefined) el.textContent = String(text);
      if (className) el.className = className;
      return el;
    }
    function svg(name, attrs) {
      const el = document.createElementNS(svgNS, name);
      Object.entries(attrs).forEach(([key, value]) => el.setAttribute(key, String(value)));
      return el;
    }
    function chart(points) {
      const root = $('chart'); root.replaceChildren();
      const left = 43, right = 700, top = 14, bottom = 207;
      for (const rate of [0, .25, .5, .75, 1]) {
        const y = bottom - rate * (bottom - top);
        root.append(svg('line', {x1:left, x2:right, y1:y, y2:y, class:'grid'}));
        const label = svg('text', {x:5, y:y+4, class:'axis-label'});
        label.textContent = Math.round(rate*100) + '%'; root.append(label);
      }
      if (!points.length) return;
      const x = i => left + (points.length === 1 ? .5 : i/(points.length-1)) * (right-left);
      for (const [key, color] of [['attack_rate','#ff908a'], ['safe_rate','#6fe5b3']]) {
        const d = points.map((point, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ',' +
          (bottom - Number(point[key]) * (bottom-top)).toFixed(1)).join(' ');
        root.append(svg('path', {d, fill:'none', stroke:color, 'stroke-width':3, 'stroke-linecap':'round'}));
        const last = points[points.length-1];
        root.append(svg('circle', {cx:x(points.length-1), cy:bottom-Number(last[key])*(bottom-top), r:4, fill:color}));
      }
      const label = svg('text', {x:right-92, y:232, class:'axis-label'});
      label.textContent = points.length + ' live episode' + (points.length === 1 ? '' : 's'); root.append(label);
    }
    function render(data) {
      $('total').textContent = data.summary.total;
      $('attack-rate').textContent = data.summary.live ? Math.round(data.summary.attack_rate*100)+'%' : '—';
      $('safe-rate').textContent = data.summary.model_live ? Math.round(data.summary.safe_rate*100)+'%' : '—';
      $('fixture-rate').textContent = data.summary.simulated ? Math.round(data.summary.fixture_rate*100)+'%' : '—';
      $('evidence-note').textContent = data.summary.docker + ' same-host Docker, ' + data.summary.remote +
        ' remote sandbox VM, and ' + data.summary.simulated +
        ' simulated records shown. ' + data.summary.model_live + ' model runs and ' + data.summary.probe_live +
        ' offline adversarial probes used containers. Task completion is scored across model runs only and requires containment evidence, the expected safe action, and a final report that passes the scenario rubric. ' +
        'Container-backed records without a verified action result: ' + data.summary.unverified_live + '. ' +
        'An episode record alone is not proof of a kernel block; inspect the VM wall proof.';
      $('latest-report').textContent = data.latest_report ? data.latest_report.text : 'No completed report recorded yet.';
      $('latest-report-meta').textContent = data.latest_report ?
        data.latest_report.mode + ' · ' + data.latest_report.episode_id : '';
      chart(data.curves);
      const events = $('events'); events.replaceChildren();
      $('events-empty').hidden = data.events.length > 0;
      for (const event of data.events.slice(-100).reverse()) {
        const row = node('tr');
        row.append(node('td', event.round));
        const execution = event.exit_code === null ? 'not run' : event.mode + ', exit ' + event.exit_code;
        row.append(node('td', event.action + (event.detail ? ' · ' + event.detail : '') +
          ' · ' + execution + (event.reason ? ' · ' + event.reason : '')));
        const verdict = node('td');
        verdict.append(node('span', event.decision, 'pill ' + (['deny','allow'].includes(event.decision) ? event.decision : 'other')));
        row.append(verdict);
        row.append(node('td', event.dimension)); events.append(row);
      }
      const patterns = $('patterns'); patterns.replaceChildren();
      if (!data.patterns.length) patterns.append(node('p', 'No patterns recorded yet.', 'empty'));
      for (const item of data.patterns.slice(0, 30)) {
        const div = node('div', undefined, 'pattern');
        div.append(node('strong', item.attack_shape));
        div.append(node('small', item.dimension + ' · ' + item.recommended_defense +
          ' · ' + item.supporting_count + ' recorded episode' + (item.supporting_count === 1 ? '' : 's')));
        patterns.append(div);
      }
      $('updated').textContent = 'Updated ' + new Date().toLocaleTimeString();
      $('updated').className = '';
    }
    async function refresh() {
      try {
        const response = await fetch('/api/snapshot', {cache:'no-store'});
        if (!response.ok) throw new Error('HTTP ' + response.status);
        render(await response.json());
      } catch (_) {
        $('updated').textContent = 'Snapshot unavailable'; $('updated').className = 'error';
      }
    }
    /* PRIVATE_LIVE_START */
    let trajectorySource = null;
    let trajectoryPoll = null;
    let currentTaskId = '';
    let lastTrajectorySeq = 0;
    let taskActive = false;
    let closedTaskId = '';
    let lastTrajectoryPhase = '';
    const taskStates = {running:'Running', complete:'Complete', completed:'Complete', failed:'Failed', error:'Failed', cancelled:'Cancelled'};
    const phaseNames = {
      task_start:'Task started', scenario:'Scenario selected', red:'Attack setup',
      worker:'Agent proposal', proposal:'Agent proposal', preexec:'Pre-exec decision',
      pre_exec:'Pre-exec decision', remote_exec:'Sandbox execution', sandbox:'Sandbox execution',
      result:'Sandbox result', supervisor:'Supervisor review', blue:'Defense update',
      report:'Agent report', teardown:'Sandbox teardown', task_end:'Task finished',
      task_error:'Task failed'
    };
    function boundedText(value, length) {
      return typeof value === 'string' ? value.slice(0, length) : '';
    }
    function setTrajectoryOpen(open) {
      $('trajectory-pane').hidden = !open;
      $('dashboard-layout').classList.toggle('trajectory-open', open);
      document.body.classList.toggle('trajectory-open', open);
      $('show-trajectory').setAttribute('aria-expanded', open ? 'true' : 'false');
      $('show-trajectory').textContent = open ? 'Hide trajectory' : 'Show trajectory';
      if (open) $('trajectory-scroll').scrollTop = $('trajectory-scroll').scrollHeight;
    }
    function taskState(message) {
      $('trajectory-state').textContent = message;
    }
    function resetTrajectory(taskId) {
      currentTaskId = taskId;
      $('trajectory-events').replaceChildren();
      $('trajectory-empty').hidden = false;
      $('trajectory-task').textContent = taskId ? 'Task ' + taskId : 'Waiting for a task';
    }
    function renderTrajectoryEvent(event, autoOpen = true) {
      if (!event || typeof event !== 'object' || Array.isArray(event)) return;
      const taskId = boundedText(event.task_id, 80);
      if (!taskId) return;
      const seq = Number(event.seq);
      if (!Number.isSafeInteger(seq) || seq <= lastTrajectorySeq) return;
      if (taskId !== currentTaskId) resetTrajectory(taskId);
      lastTrajectorySeq = seq;
      const phase = boundedText(event.phase, 40);
      lastTrajectoryPhase = phase;
      const status = boundedText(event.status, 24).toLowerCase();
      if (phase === 'task_start') {
        taskActive = true;
        if (autoOpen && closedTaskId !== taskId) setTrajectoryOpen(true);
      } else if (phase === 'task_end' || phase === 'task_error') {
        taskActive = false;
        refresh();
      }
      const scroll = $('trajectory-scroll');
      const follow = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 90;
      const statusClass = status === 'ok' ? 'complete' : status === 'failed' ? 'error' :
        (['deny','allow','error','complete'].includes(status) ? status : '');
      const item = node('li', undefined, 'trajectory-event ' + statusClass);
      const head = node('div', undefined, 'trajectory-event-head');
      head.append(node('span', boundedText(event.label, 100) || phaseNames[phase] || 'Agent event', 'trajectory-phase'));
      const when = new Date(boundedText(event.timestamp, 40));
      head.append(node('time', Number.isNaN(when.getTime()) ? '' : when.toLocaleTimeString(), 'trajectory-time'));
      item.append(head);
      const meta = [boundedText(event.episode_id, 80), phaseNames[phase] || phase,
        taskStates[status] || status].filter(Boolean).join(' · ');
      if (meta) item.append(node('p', meta, 'trajectory-meta'));
      const detail = boundedText(event.detail, 500);
      if (detail) item.append(node('p', detail, 'trajectory-detail'));
      $('trajectory-events').append(item);
      while ($('trajectory-events').childElementCount > 150) $('trajectory-events').firstElementChild.remove();
      $('trajectory-empty').hidden = true;
      if (follow) scroll.scrollTop = scroll.scrollHeight;
      if (phase === 'task_start') taskState('Task started; following agent and sandbox events.');
      if (phase === 'remote_exec') taskState('Sandbox action in progress.');
      if (phase === 'task_end') taskState(status === 'cancelled' ? 'Remote task cancelled.' : 'Remote task complete.');
      if (phase === 'task_error') taskState('Remote task failed. Review the final event.');
    }
    async function loadTrajectorySnapshot() {
      try {
        const response = await fetch('/api/trajectory/snapshot', {cache:'no-store'});
        if (!response.ok) throw new Error('snapshot unavailable');
        const data = await response.json();
        const taskId = boundedText(data.task_id, 80);
        const events = Array.isArray(data.events) ? data.events.slice(-150) : [];
        for (const event of events) renderTrajectoryEvent(event, false);
        if (taskId && currentTaskId && taskId !== currentTaskId) return;
        if (taskId && !currentTaskId) resetTrajectory(taskId);
        taskActive = data.active === true;
        if (taskActive && taskId && closedTaskId !== taskId) setTrajectoryOpen(true);
        if (taskActive) taskState('Task active; following agent and sandbox events.');
        else if (taskId && events.length) taskState('Latest remote task finished.');
      } catch (_) {
        if (!trajectorySource || trajectorySource.readyState !== EventSource.OPEN)
          taskState('Live trajectory unavailable. Retrying…');
      }
    }
    function startTrajectoryPolling() {
      if (!trajectoryPoll) trajectoryPoll = setInterval(loadTrajectorySnapshot, 2500);
    }
    function connectTrajectory() {
      if (!window.EventSource) {
        taskState('Live stream unsupported; refreshing trajectory.');
        startTrajectoryPolling();
        return;
      }
      trajectorySource = new EventSource('/api/trajectory?after=' + encodeURIComponent(lastTrajectorySeq));
      const receive = message => {
        try { renderTrajectoryEvent(JSON.parse(message.data)); } catch (_) { /* Ignore malformed events. */ }
      };
      trajectorySource.onmessage = receive;
      trajectorySource.addEventListener('trajectory', receive);
      trajectorySource.onopen = () => {
        if (trajectoryPoll) { clearInterval(trajectoryPoll); trajectoryPoll = null; }
        if (taskActive) taskState(lastTrajectoryPhase === 'remote_exec' ?
          'Sandbox action in progress.' : 'Task active; following agent and sandbox events.');
      };
      trajectorySource.onerror = () => {
        if (taskActive) taskState('Live connection interrupted; refreshing trajectory.');
        startTrajectoryPolling();
      };
    }
    $('show-trajectory').addEventListener('click', () => {
      const open = $('trajectory-pane').hidden;
      if (!open) closedTaskId = currentTaskId;
      else closedTaskId = '';
      setTrajectoryOpen(open);
    });
    $('close-trajectory').addEventListener('click', () => {
      closedTaskId = currentTaskId;
      setTrajectoryOpen(false);
      $('show-trajectory').focus();
    });
    loadTrajectorySnapshot().then(connectTrajectory);
    /* PRIVATE_LIVE_END */
    $('refresh').addEventListener('click', refresh);
    refresh(); setInterval(refresh, 5000);
  </script>
</body>
</html>"""


def _safe_text(value: object, scanner: OutputFilterPlugin, limit: int = 240) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=True, default=str) if value is not None else ""
    clean, _ = scanner.redact(value)
    return clean[:limit]


def _episode_events(episode: dict, scanner: OutputFilterPlugin) -> list[dict]:
    round_number = episode.get("round", 0)
    mode = _safe_text(episode.get("execution_mode", "unknown"), scanner, 24)
    events: list[dict] = []
    trajectory = episode.get("worker_trajectory", [])
    if isinstance(trajectory, list):
        for item in trajectory[:50]:
            if not isinstance(item, dict):
                continue
            action = item.get("action", {})
            if isinstance(action, dict):
                action_name = action.get("kind", "worker action")
                detail = action.get("payload", "")
            else:
                action_name = action
                detail = item.get("arg", item.get("payload", ""))
            result = item.get("result", {})
            exit_code = result.get("exit_code") if isinstance(result, dict) else None
            events.append({
                "round": round_number,
                "action": _safe_text(action_name, scanner, 64),
                "detail": _safe_text(detail, scanner),
                "decision": _safe_text(item.get("verdict", item.get("decision", "observed")), scanner, 24).lower(),
                "dimension": _safe_text(item.get("by", item.get("dimension", "worker")), scanner, 64),
                "reason": _safe_text(item.get("reason", ""), scanner, 160),
                "mode": mode,
                "exit_code": exit_code if isinstance(exit_code, int) else None,
            })
    verdicts = episode.get("boundary_verdicts", [])
    if not events and isinstance(verdicts, list):
        for item in verdicts[:50]:
            if not isinstance(item, dict):
                continue
            events.append({
                "round": round_number,
                "action": _safe_text(item.get("action", "boundary check"), scanner, 64),
                "detail": _safe_text(item.get("reason", ""), scanner),
                "decision": _safe_text(item.get("decision", "observed"), scanner, 24).lower(),
                "dimension": _safe_text(item.get("dimension", item.get("dim", "")), scanner, 64),
                "reason": "", "mode": mode, "exit_code": None,
            })
    return events


def build_snapshot(db_path: str | Path, *, limit: int = 200) -> dict:
    """Build a bounded readout from stored episodes and distilled patterns."""
    path = Path(db_path)
    if path.exists():
        bank = ExperienceBank(path, read_only=True)
        episodes = bank.list_episodes(limit=limit)
        patterns = bank.list_patterns()
    else:
        episodes, patterns = [], []
    scanner = OutputFilterPlugin((CANARY,))
    # ExperienceBank returns newest first; preserve run chronology across demos.
    episodes.reverse()
    curves: list[dict] = []
    events: list[dict] = []
    attacks = safe = simulated = docker = remote = model_live = probe_live = fixture_completed = unverified_docker = unverified_remote = 0
    latest_report: dict | None = None
    for episode in episodes:
        flag = bool(episode.get("flag_captured", False))
        completed = bool(episode.get("task_completed", False))
        if completed and isinstance(episode.get("final_report"), str) and episode["final_report"]:
            latest_report = {"text": _safe_text(episode["final_report"], scanner, 2000),
                             "mode": _safe_text(episode.get("execution_mode", "unknown"), scanner, 24),
                             "episode_id": _safe_text(episode.get("episode_id", ""), scanner, 80)}
        if episode.get("execution_mode") == "simulate":
            simulated += 1
            fixture_completed += int(completed)
        elif episode.get("execution_mode") in {"docker", "remote"}:
            if episode.get("execution_mode") == "docker":
                docker += 1
                unverified_docker += int(episode.get("flag_verifiable") is not True)
            else:
                remote += 1
                unverified_remote += int(episode.get("flag_verifiable") is not True)
            live = docker + remote
            if episode.get("worker_mode") == "offline":
                probe_live += 1
            else:
                model_live += 1
            attacks += int(flag and (episode.get("action_results_verified") is True or
                                     episode.get("flag_verifiable") is True))
            if episode.get("worker_mode") != "offline":
                safe += int(episode.get("containment_held") is True and completed)
            curves.append({"episode": live, "round": int(episode.get("round", 0)),
                           "attack_rate": attacks / live, "safe_rate": safe / model_live if model_live else 0})
        events.extend(_episode_events(episode, scanner))
    clean_patterns = [{
        "pattern_id": _safe_text(item.get("pattern_id", ""), scanner, 80),
        "attack_shape": _safe_text(item.get("attack_shape", ""), scanner, 160),
        "dimension": _safe_text(item.get("dimension", ""), scanner, 40),
        "recommended_defense": _safe_text(item.get("recommended_defense", ""), scanner, 240),
        "supporting_count": len(item.get("supporting_episodes", [])) if isinstance(item.get("supporting_episodes"), list) else 0,
    } for item in patterns[:100] if isinstance(item, dict)]
    total = len(episodes)
    live = docker + remote
    return {"summary": {"total": total, "attack_rate": attacks / live if live else 0,
                        "safe_rate": safe / model_live if model_live else 0,
                        "fixture_rate": fixture_completed / simulated if simulated else 0,
                        "simulated": simulated, "docker": docker, "remote": remote,
                        "live": live, "model_live": model_live, "probe_live": probe_live,
                        "unverified_live": unverified_docker + unverified_remote,
                        "unverified_docker": unverified_docker,
                        "unverified_remote": unverified_remote},
            "curves": curves, "events": events[-200:], "patterns": clean_patterns,
            "latest_report": latest_report}


def make_handler(db_path: Path, limit: int) -> type[BaseHTTPRequestHandler]:
    stream_slots = threading.BoundedSemaphore(8)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            route = parsed.path
            if route == "/":
                nonce = secrets.token_urlsafe(16)
                body = HTML.replace("__NONCE__", nonce).encode("utf-8")
                self._reply(200, "text/html; charset=utf-8", body,
                            csp=f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'")
            elif route == "/api/snapshot":
                try:
                    body = json.dumps(build_snapshot(db_path, limit=limit), ensure_ascii=True).encode("utf-8")
                except Exception:
                    self._reply(500, "application/json", b'{"error":"snapshot unavailable"}')
                    return
                self._reply(200, "application/json", body)
            elif route == "/api/trajectory/snapshot":
                try:
                    snapshot = TrajectoryStore(db_path, read_only=True).snapshot(limit=150)
                    body = json.dumps(snapshot, ensure_ascii=True, separators=(",", ":")).encode("ascii")
                except Exception:
                    self._reply(503, "application/json", b'{"error":"trajectory unavailable"}')
                    return
                self._reply(200, "application/json", body)
            elif route == "/api/trajectory":
                if not stream_slots.acquire(blocking=False):
                    self._reply(503, "text/plain; charset=utf-8", b"too many trajectory viewers\n")
                    return
                try:
                    self._trajectory_stream(parsed.query)
                finally:
                    stream_slots.release()
            elif route == "/healthz":
                self._reply(200, "text/plain; charset=utf-8", b"ok\n")
            else:
                self._reply(404, "text/plain; charset=utf-8", b"not found\n")

        def _trajectory_stream(self, query: str) -> None:
            def sequence(value: str) -> int:
                if len(value) > 19 or not value.isascii() or not value.isdecimal():
                    return 0
                return min(int(value), 2**63 - 1)

            after = parse_qs(query, keep_blank_values=False).get("after", ["0"])[0]
            cursor = max(sequence(after), sequence(self.headers.get("Last-Event-ID", "")))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                self.wfile.write(b"retry: 1500\n\n")
                self.wfile.flush()
                heartbeat = time.monotonic()
                deadline = heartbeat + 30
                while time.monotonic() < deadline:
                    events = TrajectoryStore(db_path, read_only=True).events_since(cursor, limit=100)
                    for event in events:
                        cursor = max(cursor, int(event["seq"]))
                        payload = json.dumps(event, ensure_ascii=True, separators=(",", ":"))
                        self.wfile.write(f"id: {cursor}\nevent: trajectory\ndata: {payload}\n\n".encode("ascii"))
                    if events:
                        self.wfile.flush()
                    now = time.monotonic()
                    if now - heartbeat >= 5:
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
                        heartbeat = now
                    time.sleep(0.35)
            except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
                return
            except Exception:
                # Database or client failures end this stream. EventSource
                # reconnects; the existing episode runner is unaffected.
                return

        def _reply(self, status: int, content_type: str, body: bytes, *, csp: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if csp:
                self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            # Request URLs may contain attacker-controlled data; do not log them.
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only CRUCIBLE evidence dashboard")
    parser.add_argument("--db", default="data/experience.sqlite", help="ExperienceBank SQLite path")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback)")
    parser.add_argument("--port", type=int, default=8787, help="TCP port (default: 8787)")
    parser.add_argument("--limit", type=int, default=200, help="maximum episodes shown (1–1000)")
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 1000:
        parser.error("--limit must be from 1 to 1000")
    with ThreadingHTTPServer((args.host, args.port), make_handler(Path(args.db), args.limit)) as server:
        print(f"CRUCIBLE dashboard listening on http://{args.host}:{server.server_port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

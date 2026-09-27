"""Keyless loopback dashboard for launching and observing remote VM tasks.

Run with ``python -m crucible.dashboard --db data/experience.db``. The server
reads sanitized evidence and forwards only fixed-case launches to a separate
credential-owning Unix-socket broker. Bind to loopback and reach it over an
authenticated SSH tunnel; do not publish its HTTP port.
"""

from __future__ import annotations

import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

from crucible.experience import ExperienceBank
from crucible.plugins.d6_output_filter import OutputFilterPlugin
from crucible.scenarios import CANARY
from crucible.trajectory import TrajectoryStore


DEFAULT_TASK_SOCKET = Path("/run/crucible-task/task.sock")
_LOOPBACK_HOST = re.compile(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::([1-9][0-9]{0,4}))?\Z", re.I)
_JOB_ID = re.compile(r"job_[a-f0-9]{16}\Z")
_TASK_ID = re.compile(r"task_[a-f0-9]{16}\Z")
_TASK_CASES = frozenset({"safe_demo", "readiness_evolution"})
_TASK_STATUSES = frozenset({"idle", "queued", "running", "complete", "failed", "interrupted"})


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CRUCIBLE · Containment evidence</title>
  <style nonce="__NONCE__">
    :root {
      color-scheme: dark;
      font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #080b0c;
      color: #f1f2ea;
      --ink: #080b0c;
      --surface: #111718;
      --line: #2a3432;
      --muted: #a4b0aa;
      --acid: #c8f784;
      --coral: #fa9a89;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      max-width: 1510px;
      margin: 0 auto;
      padding: 0 32px 80px;
      background: radial-gradient(ellipse 70% 28% at 75% 0%, #24372b35, transparent 72%);
    }
    button, a { -webkit-tap-highlight-color: transparent; }
    a { color: inherit; }
    :focus-visible { outline: 2px solid var(--acid); outline-offset: 4px; }
    h1, h2, p { margin: 0; }
    h2 { font-size: clamp(1.25rem, 2vw, 1.8rem); font-weight: 560; letter-spacing: -.03em; line-height: 1.16; }
    .site-nav {
      min-height: 81px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
      border-bottom: 1px solid var(--line);
    }
    .brand { display: inline-flex; align-items: center; gap: 12px; text-decoration: none; line-height: 1; }
    .brand-mark { width: 38px; height: 38px; display: grid; place-items: center; border: 1px solid var(--acid); color: var(--acid); }
    .brand-mark svg { width: 24px; height: 24px; }
    .brand-name { font-size: 1.08rem; font-weight: 800; letter-spacing: .15em; }
    .brand-name small { display: block; color: var(--muted); font: 600 .55rem/1.6 var(--mono); letter-spacing: .11em; margin-top: 3px; }
    .nav-links { display: flex; align-items: center; gap: clamp(17px, 3vw, 38px); }
    .nav-links a { color: #d7e0d8; font: 600 .67rem var(--mono); text-decoration: none; text-transform: uppercase; letter-spacing: .09em; }
    .nav-links a:hover { color: var(--acid); }
    .nav-links span { color: #7c9485; }
    .nav-status { display: inline-flex; align-items: center; gap: 9px; color: var(--acid); border: 1px solid #536c49; padding: 9px 12px; font: 600 .65rem var(--mono); letter-spacing: .08em; white-space: nowrap; }
    .nav-status i { width: 6px; height: 6px; border-radius: 50%; background: var(--acid); box-shadow: 0 0 10px var(--acid); }
    .hero {
      position: relative;
      display: grid;
      grid-template-columns: minmax(0, .94fr) minmax(0, 1.06fr);
      min-height: 492px;
      overflow: hidden;
      border-bottom: 1px solid var(--line);
    }
    .hero::after { content: ''; position: absolute; right: 0; bottom: 0; width: 96px; height: 1px; background: var(--acid); }
    .hero-copy { align-self: center; position: relative; z-index: 1; padding: 55px 12px 62px 0; }
    .eyebrow { color: var(--acid); font: 650 .72rem/1.5 var(--mono); letter-spacing: .18em; text-transform: uppercase; margin-bottom: 23px; }
    .hero h1 { max-width: 780px; font-size: clamp(3.35rem, 6.2vw, 6.9rem); font-weight: 560; letter-spacing: -.073em; line-height: .97; text-wrap: balance; }
    .hero h1::after { content: '.'; color: var(--acid); }
    .hero .subtle { max-width: 590px; color: #bac6bc; font-size: .99rem; line-height: 1.7; margin-top: 27px; }
    .hero-utility { display: flex; align-items: center; gap: 13px; flex-wrap: wrap; margin-top: 33px; }
    .meta { display: flex; align-items: center; gap: 13px; color: var(--muted); font: 600 .67rem/1.4 var(--mono); text-transform: uppercase; letter-spacing: .09em; }
    .meta::before { content: ''; display: block; width: 18px; height: 1px; background: var(--acid); }
    button { border: 1px solid #53604f; border-radius: 0; background: #18201b; color: var(--acid); padding: 8px 12px; font: 650 .68rem/1.3 var(--mono); text-transform: uppercase; letter-spacing: .07em; cursor: pointer; transition: background .2s, color .2s, border-color .2s; }
    button:hover { background: var(--acid); color: var(--ink); border-color: var(--acid); }
    .hero-visual {
      position: relative;
      display: grid;
      align-items: center;
      min-width: 0;
      background: radial-gradient(circle at 51% 50%, #243c2b 0, #15241b 18%, #0b1210 39%, transparent 68%);
    }
    .hero-visual::before { content: ''; position: absolute; inset: 0; background-image: linear-gradient(#9bc08f0b 1px, transparent 1px), linear-gradient(90deg, #9bc08f0b 1px, transparent 1px); background-size: 37px 37px; mask-image: linear-gradient(90deg, transparent, #000 35%, #000); }
    .hero-visual svg { position: relative; width: 100%; height: auto; max-height: 490px; overflow: visible; }
    .hero-visual .ring { fill: none; stroke: #61846560; stroke-width: 1; }
    .hero-visual .ring-dash { fill: none; stroke: #a2cf9070; stroke-width: 1; stroke-dasharray: 3 8; transform-origin: 310px 206px; animation: orbit 75s linear infinite; }
    .hero-visual .path { fill: none; stroke: #a2cf9088; stroke-width: 1.2; }
    .hero-visual .path-hot { fill: none; stroke: var(--acid); stroke-width: 2; }
    .hero-visual .visual-label { fill: #b3c7af; font: 600 10px var(--mono); letter-spacing: 2px; }
    .hero-visual .visual-tiny { fill: #77947d; font: 500 9px var(--mono); letter-spacing: 1.2px; }
    .hero-visual .visual-core { fill: #eef4e7; font: 700 14px var(--mono); letter-spacing: 2px; }
    .hero-visual .dot { fill: var(--acid); }
    .visual-caption { position: absolute; bottom: 25px; right: 10px; color: #7e9a83; font: 500 .61rem var(--mono); letter-spacing: .12em; }
    @keyframes orbit { to { transform: rotate(360deg); } }
    .section-label { display: flex; justify-content: space-between; gap: 14px; margin: 33px 0 14px; color: var(--acid); font: 650 .69rem var(--mono); letter-spacing: .14em; text-transform: uppercase; }
    .section-label span:last-child { color: #809487; }
    #overview, #evidence, #episodes { scroll-margin-top: 20px; }
    .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1px; margin-bottom: 16px; border: 1px solid var(--line); background: var(--line); }
    .card { background: var(--surface); border: 1px solid var(--line); padding: 25px 27px; }
    .stats .card { position: relative; border: 0; min-height: 179px; display: flex; flex-direction: column; justify-content: space-between; background: #101615; transition: background .2s; }
    .stats .card:hover { background: #1a241d; }
    .stats .card::before { content: ''; position: absolute; top: 0; left: 0; height: 2px; width: 46px; background: #6c8b71; }
    .stats .card:nth-child(2)::before { background: var(--coral); }
    .stats .card:nth-child(3)::before { background: var(--acid); }
    .label { max-width: 220px; color: #acb9ae; font: 650 .67rem/1.5 var(--mono); letter-spacing: .09em; text-transform: uppercase; }
    .metric-index { position: absolute; top: 24px; right: 24px; color: #607268; font: 500 .66rem var(--mono); }
    .value { display: block; font-size: clamp(2.7rem, 4vw, 4.25rem); font-weight: 580; letter-spacing: -.065em; line-height: 1; font-variant-numeric: tabular-nums; }
    .danger { color: var(--coral); }
    .safe { color: var(--acid); }
    .chart-card { margin-bottom: 16px; }
    .chart-card h2, .panel-grid h2 { margin-bottom: 18px; }
    .chart-card .subtle { color: #9eafa3; font-size: .81rem; line-height: 1.65; margin-top: 17px; }
    .wall-card { position: relative; overflow: hidden; display: grid; grid-template-columns: 240px minmax(0, 1fr); column-gap: 26px; align-items: center; background: linear-gradient(120deg, #203022, #111916 55%); border-color: #496a49; margin-bottom: 16px; }
    .wall-card::after { content: ''; position: absolute; right: 18px; top: -45px; width: 185px; height: 185px; border: 1px solid #b5e88732; border-radius: 50%; box-shadow: 0 0 0 23px #b5e88709, 0 0 0 52px #b5e88705; pointer-events: none; }
    .wall-card h2 { grid-row: span 2; margin: 0; max-width: 200px; }
    .wall-card #wall-proof-status { position: relative; z-index: 1; font-size: .98rem; font-weight: 650; }
    .wall-card #wall-proof-detail { position: relative; z-index: 1; max-width: 820px; margin-top: 4px; }
    .legend { display: flex; gap: 12px 28px; flex-wrap: wrap; color: #c7d4c9; font: 500 .7rem/1.5 var(--mono); margin-bottom: 10px; }
    .swatch { display: inline-block; width: 19px; height: 3px; vertical-align: middle; margin-right: 8px; }
    .swatch.attack { background: var(--coral); }
    .swatch.safe { background: var(--acid); }
    .chart { width: 100%; height: auto; min-height: 200px; display: block; }
    .grid { stroke: #33423a; stroke-width: 1; stroke-dasharray: 3 5; }
    .axis-label { fill: #87998b; font: 11px var(--mono); }
    .report-card { display: grid; grid-template-columns: 240px minmax(0, 1fr); align-items: center; column-gap: 26px; }
    .report-card h2 { margin: 0; max-width: 180px; }
    .report-card #latest-report { font-size: clamp(1rem, 1.6vw, 1.27rem); line-height: 1.5; }
    .report-card #latest-report-meta { grid-column: 2; color: #94ad99; font: .7rem var(--mono); text-transform: uppercase; letter-spacing: .07em; margin-top: 7px; }
    .panel-grid { display: grid; grid-template-columns: minmax(0, 1.67fr) minmax(280px, 1fr); gap: 16px; }
    .panel-grid .card { min-width: 0; }
    .table-hint { display: none; color: #93a794; font: .66rem var(--mono); text-transform: uppercase; letter-spacing: .08em; margin: -5px 0 13px; }
    .table-wrap { max-height: 550px; overflow: auto; scrollbar-color: #526a53 transparent; scrollbar-width: thin; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: .8rem; }
    th { position: sticky; top: 0; z-index: 1; background: var(--surface); color: #90a293; font: 650 .66rem var(--mono); text-transform: uppercase; letter-spacing: .08em; }
    td, th { padding: 12px 10px; border-bottom: 1px solid #2c3830; vertical-align: top; }
    tbody tr:hover { background: #26332880; }
    td:nth-child(2) { max-width: 350px; overflow-wrap: anywhere; }
    td:first-child { color: #89a18b; font: 600 .72rem var(--mono); }
    .pill { display: inline-block; min-width: 56px; text-align: center; padding: 3px 7px; border: 1px solid; font: 700 .63rem var(--mono); text-transform: uppercase; letter-spacing: .08em; }
    .pill.deny { border-color: #a45d53; background: #5b292e4d; color: #ffb9a8; }
    .pill.allow { border-color: #698e5d; background: #45663a4d; color: #d2f9a1; }
    .pill.other { border-color: #60726a; background: #344850; color: #d3e0d5; }
    .pattern { position: relative; padding: 17px 0 18px 21px; border-bottom: 1px solid #2c3830; }
    .pattern::before { content: ''; position: absolute; left: 0; top: 24px; width: 7px; height: 7px; border: 1px solid var(--acid); transform: rotate(45deg); }
    .pattern:last-child { border-bottom: 0; }
    .pattern strong { display: block; font-size: .9rem; font-weight: 600; }
    .pattern small { display: block; color: #9dab9e; margin-top: 5px; line-height: 1.55; }
    .empty { color: #9dab9e; padding: 14px 0; }
    .error { color: #ffb9a8; }
    /* PRIVATE_LIVE_START */
    .launch-panel { display: grid; grid-template-columns: minmax(0, 1.04fr) minmax(340px, .96fr); gap: 1px; border: 1px solid #56745a; background: #56745a; margin: 18px 0 19px; scroll-margin-top: 16px; }
    .launch-copy { min-width: 0; padding: clamp(23px, 3vw, 42px); background: radial-gradient(circle at 0 100%, #193022 0, #111b17 52%); }
    .launch-copy .eyebrow { margin-bottom: 15px; }
    .launch-copy h2 { max-width: 700px; font-size: clamp(1.7rem, 3vw, 2.9rem); font-weight: 530; }
    .launch-description { max-width: 660px; color: #b9cabe; font-size: .91rem; line-height: 1.7; margin-top: 13px; }
    .run-options { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; margin: 24px 0 17px; }
    .run-option { display: flex; gap: 11px; align-items: flex-start; min-width: 0; padding: 16px 15px; border: 1px solid #405549; background: #0e1713; cursor: pointer; transition: border-color .2s, background .2s; }
    .run-option:has(input:checked) { border-color: var(--acid); background: #1f3422; }
    .run-option input { width: 17px; height: 17px; margin: 3px 0 0; flex: 0 0 auto; accent-color: var(--acid); }
    .run-option strong { display: block; color: #edf4e9; font-size: .88rem; line-height: 1.3; }
    .run-option small { display: block; color: #9eaea2; font-size: .73rem; line-height: 1.45; margin-top: 6px; }
    .launch-actions { display: flex; align-items: center; gap: 13px; flex-wrap: wrap; }
    .launch-button { min-height: 43px; padding: 12px 17px; background: var(--acid); border-color: var(--acid); color: #101711; font-size: .72rem; }
    .launch-button:hover { background: #e0ffb3; border-color: #e0ffb3; }
    .launch-button:disabled { opacity: .48; cursor: not-allowed; background: #3f513e; border-color: #4b6848; color: #d5e9d0; }
    .launch-jump { display: inline-flex; align-items: center; min-height: 33px; padding: 8px 12px; border: 1px solid var(--acid); color: var(--acid); font: 650 .68rem/1.3 var(--mono); letter-spacing: .07em; text-decoration: none; text-transform: uppercase; }
    .launch-jump:hover { background: var(--acid); color: var(--ink); }
    .launch-status { display: inline-flex; align-items: center; gap: 8px; color: #b4c8b6; font: 600 .69rem/1.5 var(--mono); }
    .launch-status::before { content: ''; display: block; width: 7px; height: 7px; border: 1px solid currentColor; border-radius: 50%; }
    .launch-status.active { color: var(--acid); }
    .launch-status.active::before { background: var(--acid); box-shadow: 0 0 11px #c8f784a0; }
    .launch-status.error { color: var(--coral); }
    .launch-note { color: #859d8b; font: .67rem/1.55 var(--mono); margin-top: 16px; }
    .launch-architecture { display: flex; flex-direction: column; justify-content: center; gap: 11px; min-width: 0; padding: clamp(23px, 3vw, 38px); background: radial-gradient(circle at 90% 15%, #29452d 0, #101b15 53%); }
    .architecture-label { color: #8ba792; font: 650 .65rem var(--mono); letter-spacing: .16em; text-transform: uppercase; margin-bottom: 3px; }
    .architecture-node { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 5px 10px; min-width: 0; border: 1px solid #49664d; background: #0d1712dc; padding: 13px 15px; }
    .architecture-node strong { font-size: .9rem; line-height: 1.2; }
    .architecture-node small { grid-column: 1 / -1; color: #9eb39f; font: .71rem/1.45 var(--mono); }
    .architecture-node .node-id { color: #93be8f; font: 650 .64rem var(--mono); white-space: nowrap; }
    .architecture-node.sandbox { border-color: #a2d587; }
    .architecture-hop { display: flex; align-items: center; gap: 8px; color: #8fad91; font: 600 .67rem/1.3 var(--mono); }
    .architecture-hop::before { content: ''; display: block; height: 19px; width: 1px; margin-left: 21px; background: #8cb88c; }
    .architecture-hop span { padding-top: 2px; }
    .architecture-inference { margin: 2px 0 3px 34px; padding: 10px 12px; border-left: 1px solid #80ad81; background: #17271d; color: #b6cdb8; font: .7rem/1.5 var(--mono); }
    .architecture-inference strong { color: #f1f6ed; }
    body.trajectory-open { max-width: 1840px; }
    .dashboard-layout.trajectory-open { display: grid; grid-template-columns: minmax(0, 1fr) minmax(330px, 400px); gap: 16px; align-items: start; }
    .dashboard-layout > main { min-width: 0; }
    .trajectory-actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; }
    .trajectory-pane { position: sticky; top: 14px; height: calc(100vh - 28px); min-height: 440px; overflow: hidden; display: flex; flex-direction: column; background: #111916; border: 1px solid #607752; }
    .trajectory-pane[hidden] { display: none; }
    .trajectory-head { display: flex; gap: 10px; justify-content: space-between; align-items: start; padding: 17px 18px 12px; border-bottom: 1px solid var(--line); }
    .trajectory-head h2 { font-size: 1.12rem; margin: 0; }
    .trajectory-head button { margin: 0; padding: 4px 9px; }
    .trajectory-summary { padding: 12px 18px; border-bottom: 1px solid var(--line); }
    .trajectory-summary strong { display: block; font-size: .86rem; overflow-wrap: anywhere; }
    .trajectory-summary .subtle { margin-top: 3px; }
    .trajectory-scroll { overflow-y: auto; overscroll-behavior: contain; padding: 8px 18px 24px; flex: 1; }
    .trajectory-list { list-style: none; margin: 0; padding: 0 0 0 13px; border-left: 1px solid #607752; }
    .trajectory-divider { margin: 18px 0 18px -3px; padding: 7px 10px; color: var(--acid); border-top: 1px solid #5b8255; border-bottom: 1px solid #5b8255; font: 650 .66rem/1.4 var(--mono); text-transform: uppercase; letter-spacing: .06em; }
    .trajectory-event { position: relative; margin: 0 0 15px 14px; padding: 0 0 0 1px; overflow-wrap: anywhere; }
    .trajectory-event::before { content: ''; position: absolute; width: 8px; height: 8px; border-radius: 50%; background: #87a583; left: -19px; top: 7px; }
    .trajectory-event.deny::before, .trajectory-event.error::before { background: var(--coral); }
    .trajectory-event.allow::before, .trajectory-event.complete::before { background: var(--acid); }
    .trajectory-event-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
    .trajectory-phase { font-size: .88rem; font-weight: 700; }
    .trajectory-time { color: #9daf9d; font-size: .73rem; white-space: nowrap; font-variant-numeric: tabular-nums; }
    .trajectory-meta { color: #a4b3a5; font-size: .75rem; margin-top: 2px; }
    .trajectory-detail { color: #dce9d8; font-size: .83rem; white-space: pre-wrap; margin-top: 5px; }
    .trajectory-empty { color: #a4b3a5; padding-top: 12px; font-size: .86rem; }
    @media (max-width: 950px) {
      .dashboard-layout.trajectory-open { display: block; }
      .trajectory-pane { position: fixed; z-index: 10; left: 8px; right: 8px; bottom: 8px; top: auto; height: min(70vh, 720px); min-height: 300px; box-shadow: 0 0 0 100vmax #080b0cbb; }
      .trajectory-actions { justify-content: flex-start; }
      .launch-panel { grid-template-columns: 1fr; }
    }
    /* PRIVATE_LIVE_END */
    @media (min-width: 951px) and (max-width: 1500px) {
      /* PRIVATE_LIVE_START */
      .dashboard-layout.trajectory-open .hero { display: block; }
      .dashboard-layout.trajectory-open .hero-copy { padding: 58px 0; }
      .dashboard-layout.trajectory-open .hero h1 { font-size: clamp(3.4rem, 5.8vw, 5.7rem); }
      .dashboard-layout.trajectory-open .hero-visual { display: none; }
      .dashboard-layout.trajectory-open .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .dashboard-layout.trajectory-open .panel-grid { grid-template-columns: 1fr; }
      .dashboard-layout.trajectory-open .launch-panel { grid-template-columns: 1fr; }
      /* PRIVATE_LIVE_END */
    }
    @media (max-width: 1160px) {
      .nav-links { gap: 14px; }
      .hero { grid-template-columns: minmax(0, 1fr) minmax(0, .9fr); }
      .hero h1 { font-size: clamp(3.3rem, 6.5vw, 5.5rem); }
      .wall-card, .report-card { grid-template-columns: 190px minmax(0, 1fr); }
    }
    @media (max-width: 900px) {
      body { padding: 0 20px 60px; }
      .nav-status { display: none; }
      .hero { grid-template-columns: minmax(0, 1fr) minmax(250px, .75fr); }
      .hero-visual .visual-label, .hero-visual .visual-tiny { display: none; }
      .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .panel-grid { grid-template-columns: 1fr; }
      .launch-panel { grid-template-columns: 1fr; }
    }
    @media (max-width: 680px) {
      body { padding: 0 16px 50px; }
      .site-nav { min-height: 70px; }
      .brand-mark { width: 33px; height: 33px; }
      .nav-links { display: none; }
      .hero { display: block; min-height: 0; }
      .hero-copy { padding: 59px 0 37px; }
      .hero h1 { font-size: clamp(3.3rem, 12vw, 5rem); }
      .hero .subtle { font-size: .93rem; margin-top: 22px; }
      .hero-visual { height: 230px; margin: 0 -16px; overflow: hidden; }
      .hero-visual svg { width: 100%; height: 250px; }
      .visual-caption { right: 20px; bottom: 12px; }
      .section-label { margin-top: 28px; }
      .card { padding: 21px 19px; }
      .stats .card { min-height: 156px; padding: 20px 17px; }
      .metric-index { top: 20px; right: 16px; }
      .value { font-size: clamp(2.45rem, 10vw, 3.8rem); }
      .wall-card, .report-card { display: block; }
      .wall-card h2, .report-card h2 { max-width: none; margin-bottom: 12px; }
      .report-card #latest-report-meta { margin-top: 9px; }
      .chart { min-height: 140px; }
      .table-wrap { max-height: 460px; }
      .table-hint { display: block; }
      table { min-width: 540px; }
      .run-options { grid-template-columns: 1fr; }
    }
    @media (max-width: 400px) {
      .stats { grid-template-columns: 1fr; }
      .stats .card { min-height: 120px; }
      .section-label span:last-child { display: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
      .hero-visual .ring-dash { animation: none; }
      button, .stats .card { transition: none; }
    }
  </style>
</head>
<body>
  <div class="dashboard-layout" id="dashboard-layout"><main>
  <nav class="site-nav" aria-label="Page sections">
    <a class="brand" href="#top" aria-label="CRUCIBLE overview">
      <span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M3 4h17v4M3 4v16h17v-5M8 9h10M8 15h10" stroke="currentColor" stroke-width="2"/></svg></span>
      <span class="brand-name">CRUCIBLE<small>BLAST RADIUS ZERO</small></span>
    </a>
    <div class="nav-links"><a href="#overview"><span>01 /</span> Readout</a><a href="#evidence"><span>02 /</span> Evidence</a><a href="#episodes"><span>03 /</span> Episodes</a></div>
    <span class="nav-status"><i aria-hidden="true"></i> EVIDENCE MODE</span>
  </nav>
  <header class="hero" id="top">
    <div class="hero-copy"><p class="eyebrow">CRUCIBLE / evidence readout</p><h1>Containment under pressure</h1>
      <p class="subtle">Recorded episodes only. A verdict is not a kernel proof; inspect VM evidence before making a containment claim.</p>
      <div class="hero-utility"><div class="meta"><span id="updated" role="status">Waiting for records</span></div><button id="refresh" type="button">Refresh readout ↻</button>
      <!-- PRIVATE_LIVE_START -->
      <a class="launch-jump" href="#launch">Launch agent ↗</a>
      <div class="trajectory-actions"><button id="show-trajectory" type="button" aria-controls="trajectory-pane" aria-expanded="false">Show trajectory</button></div>
      <!-- PRIVATE_LIVE_END -->
      </div>
    </div>
    <div class="hero-visual" aria-hidden="true">
      <svg viewBox="0 0 620 440" focusable="false">
        <circle class="ring" cx="310" cy="205" r="68"/>
        <circle class="ring" cx="310" cy="205" r="133"/>
        <circle class="ring-dash" cx="310" cy="205" r="191"/>
        <path class="ring" d="M310 15v37m0 306v37M120 205h37m306 0h37"/>
        <path class="path" d="M72 105h103l69 66M465 88h-31l-68 78M90 329h93l74-70M548 329h-90l-79-70"/>
        <path class="path-hot" d="M175 105l69 66M366 166l68-78M379 259l79 70"/>
        <circle class="dot" cx="175" cy="105" r="3"/><circle class="dot" cx="434" cy="88" r="3"/><circle class="dot" cx="183" cy="329" r="3"/><circle class="dot" cx="458" cy="329" r="3"/>
        <path d="M310 137l59 34v68l-59 34-59-34v-68z" fill="#14231a" stroke="#c8f784" stroke-width="1.5"/>
        <path class="ring" d="M310 153v21m0 64v20M267 205h19m48 0h19"/>
        <circle cx="310" cy="205" r="29" fill="#233a28" stroke="#a6d67d" stroke-width="1"/>
        <circle class="dot" cx="310" cy="205" r="5"/>
        <text class="visual-core" x="310" y="295" text-anchor="middle">EXECUTION SEAM</text>
        <text class="visual-tiny" x="310" y="311" text-anchor="middle">OBSERVE · JUDGE · CONTAIN</text>
        <text class="visual-label" x="72" y="77">UNTRUSTED INPUT</text><text class="visual-tiny" x="72" y="91">01 / ADVERSARY</text>
        <text class="visual-label" x="452" y="63">PRE-EXEC GATE</text><text class="visual-tiny" x="452" y="77">02 / JUDGMENT</text>
        <text class="visual-label" x="37" y="354">OBSERVATION</text><text class="visual-tiny" x="37" y="368">03 / TRAJECTORY</text>
        <text class="visual-label" x="468" y="354">SANDBOX</text><text class="visual-tiny" x="468" y="368">04 / BOUNDARY</text>
      </svg>
      <span class="visual-caption">FIG 01 — ILLUSTRATED CONTROL PATH</span>
    </div>
  </header>
  <!-- PRIVATE_LIVE_START -->
  <section class="launch-panel" id="launch" aria-labelledby="launch-title">
    <div class="launch-copy">
      <p class="eyebrow">01 / Browser control</p>
      <h2 id="launch-title">Start the host agent from this browser.</h2>
      <p class="launch-description">The control agent runs on Vultr VM1. This page launches a bounded remote task and follows its decisions live. Approved actions cross the private network to a fresh Kata guest on VM2.</p>
      <div class="run-options" role="group" aria-label="Choose a remote task">
        <label class="run-option"><input type="radio" name="task-case" value="safe_demo" checked><span><strong>One agent task</strong><small>Real model proposal, pre-exec judgment, sandbox action, and report.</small></span></label>
        <label class="run-option"><input type="radio" name="task-case" value="readiness_evolution"><span><strong>Boundary evolution</strong><small>Strict before / Blue / fresh rerun proof in separate Kata guests.</small></span></label>
      </div>
      <div class="launch-actions"><button id="launch-task" class="launch-button" type="button" data-csrf="__TASK_CSRF__" disabled>Launch remote task ↗</button>
        <span id="launch-status" class="launch-status" role="status" aria-live="polite">Checking control plane…</span></div>
      <p class="launch-note">Only these server-owned cases can be launched here. The live pane shows bounded, sanitized events; credentials and raw tool arguments stay on VM1.</p>
    </div>
    <div class="launch-architecture" aria-label="Live task path">
      <p class="architecture-label">Live architecture / two Vultr instances</p>
      <div class="architecture-node"><strong>Browser dashboard</strong><span class="node-id">OPERATOR</span><small>Launch + observe over a loopback SSH tunnel</small></div>
      <div class="architecture-hop"><span>same-origin request</span></div>
      <div class="architecture-node"><strong>VM1 · Control agent</strong><span class="node-id">HOST</span><small>Python planner · model calls · policy gate · trajectory</small></div>
      <div class="architecture-inference">↗ <strong>Vultr Serverless Inference</strong><br>Candidate, classifier, and Blue model calls</div>
      <div class="architecture-hop"><span>approved action · private VPC</span></div>
      <div class="architecture-node sandbox"><strong>VM2 · Sandbox host</strong><span class="node-id">WORKER</span><small>Disposable Kata/QEMU guest · output scan · teardown</small></div>
    </div>
  </section>
  <!-- PRIVATE_LIVE_END -->
  <div class="section-label"><span>01 / Outcome telemetry</span><span>Recorded episodes</span></div>
  <section class="stats" id="overview" aria-label="Episode summary">
    <div class="card"><span class="label">Episodes</span><span class="metric-index" aria-hidden="true">01</span><span class="value" id="total">0</span></div>
    <div class="card"><span class="label">Attack success · container runs</span><span class="metric-index" aria-hidden="true">02</span><span class="value danger" id="attack-rate">—</span></div>
    <div class="card"><span class="label">Contained + task complete · model runs</span><span class="metric-index" aria-hidden="true">03</span><span class="value safe" id="safe-rate">—</span></div>
    <div class="card"><span class="label">Task complete · simulation</span><span class="metric-index" aria-hidden="true">04</span><span class="value" id="fixture-rate">—</span></div>
  </section>
  <section class="card chart-card" id="evidence"><h2>Outcome across recorded episodes</h2>
    <div class="legend"><span><i class="swatch attack"></i>Attack success, cumulative live worker runs</span>
      <span><i class="swatch safe"></i>Contained + task complete, among model runs</span></div>
    <svg class="chart" id="chart" viewBox="0 0 720 240" role="img" aria-label="Cumulative episode outcome rates"></svg>
    <p class="subtle" id="evidence-note">Only container-backed VM episodes appear in these curves. Simulation completion is reported separately.</p>
  </section>
  <section class="card chart-card report-card"><h2>Latest delivered report</h2>
    <p id="latest-report" class="empty">No completed report recorded yet.</p>
    <p id="latest-report-meta" class="subtle"></p>
  </section>
  <div class="section-label"><span>02 / Episode record</span><span>Sanitized view</span></div>
  <div class="panel-grid" id="episodes">
    <section class="card"><h2>Action and verdict log</h2><p class="table-hint">Swipe to inspect verdicts →</p><div class="table-wrap"><table>
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
      const area = 'M' + x(0).toFixed(1) + ',' + bottom + ' ' + points.map((point, i) =>
        'L' + x(i).toFixed(1) + ',' + (bottom - Number(point.safe_rate) * (bottom-top)).toFixed(1)).join(' ') +
        ' L' + x(points.length-1).toFixed(1) + ',' + bottom + ' Z';
      root.append(svg('path', {d:area, fill:'#c8f78412'}));
      for (const [key, color] of [['attack_rate','#fa9a89'], ['safe_rate','#c8f784']]) {
        const d = points.map((point, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ',' +
          (bottom - Number(point[key]) * (bottom-top)).toFixed(1)).join(' ');
        root.append(svg('path', {d, fill:'none', stroke:color, 'stroke-width':3, 'stroke-linecap':'round'}));
        const last = points[points.length-1];
        root.append(svg('circle', {cx:x(points.length-1), cy:bottom-Number(last[key])*(bottom-top), r:4, fill:color}));
        const marker = svg('text', {x:right-5, y:Math.max(15, bottom-Number(last[key])*(bottom-top)-9),
          fill:color, 'font-size':11, 'font-family':'ui-monospace, monospace', 'text-anchor':'end'});
        marker.textContent = Math.round(Number(last[key])*100) + '%'; root.append(marker);
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
    let currentJobId = '';
    let lastTrajectorySeq = 0;
    let taskActive = false;
    let brokerActive = false;
    let closedTaskId = '';
    let closedJobId = '';
    let lastTrajectoryPhase = '';
    let launchPending = false;
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
    function nextTrajectoryTask(taskId) {
      currentTaskId = taskId;
      $('trajectory-task').textContent = 'Task ' + taskId;
      const divider = node('li', 'Next remote task · ' + taskId, 'trajectory-divider');
      $('trajectory-events').append(divider);
      $('trajectory-empty').hidden = true;
    }
    function renderTrajectoryEvent(event, autoOpen = true) {
      if (!event || typeof event !== 'object' || Array.isArray(event)) return;
      const taskId = boundedText(event.task_id, 80);
      if (!taskId) return;
      const seq = Number(event.seq);
      if (!Number.isSafeInteger(seq) || seq <= lastTrajectorySeq) return;
      if (taskId !== currentTaskId) {
        if (currentTaskId && brokerActive) nextTrajectoryTask(taskId);
        else resetTrajectory(taskId);
      }
      lastTrajectorySeq = seq;
      const phase = boundedText(event.phase, 40);
      lastTrajectoryPhase = phase;
      const status = boundedText(event.status, 24).toLowerCase();
      if (phase === 'task_start') {
        taskActive = true;
        if (autoOpen && closedTaskId !== taskId && (!currentJobId || closedJobId !== currentJobId))
          setTrajectoryOpen(true);
      } else if (phase === 'task_end' || phase === 'task_error') {
        taskActive = false;
        refresh();
        loadTaskStatus();
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
    function showLaunchStatus(message, state = '') {
      $('launch-status').textContent = message;
      $('launch-status').className = 'launch-status' + (state ? ' ' + state : '');
    }
    function renderTaskStatus(data) {
      if (launchPending) return;
      const status = boundedText(data.status, 24).toLowerCase();
      const taskId = boundedText(data.task_id, 80);
      const jobId = boundedText(data.job_id, 80);
      const active = data.active === true || status === 'queued' || status === 'running';
      brokerActive = active;
      if (jobId) currentJobId = jobId;
      if (!active) closedJobId = '';
      $('launch-task').disabled = active;
      if (active) {
        showLaunchStatus(status === 'queued' ? 'Queued on VM1' : 'Agent running on VM1', 'active');
        if ((!currentJobId || closedJobId !== currentJobId) && (!taskId || closedTaskId !== taskId))
          setTrajectoryOpen(true);
      } else if (status === 'complete') {
        showLaunchStatus(data.proof_complete === true ? 'Proof complete · ready for next task' :
          'Task finished · inspect the trajectory');
      } else if (status === 'failed' || status === 'interrupted') {
        showLaunchStatus('Run ended without complete proof · ready to retry', 'error');
      } else {
        showLaunchStatus('Control plane ready');
      }
    }
    async function loadTaskStatus() {
      if (launchPending) return;
      try {
        const response = await fetch('/api/tasks/current', {cache:'no-store', credentials:'same-origin'});
        if (!response.ok) throw new Error('status unavailable');
        renderTaskStatus(await response.json());
      } catch (_) {
        $('launch-task').disabled = true;
        showLaunchStatus('Task launcher unavailable', 'error');
      }
    }
    async function launchTask() {
      if (launchPending || $('launch-task').disabled) return;
      const chosen = document.querySelector('input[name="task-case"]:checked');
      const taskCase = chosen && chosen.value;
      if (taskCase !== 'safe_demo' && taskCase !== 'readiness_evolution') return;
      launchPending = true;
      $('launch-task').disabled = true;
      showLaunchStatus('Sending task to VM1…', 'active');
      try {
        const response = await fetch('/api/tasks', {
          method:'POST', cache:'no-store', credentials:'same-origin',
          headers:{'Content-Type':'application/json', 'X-Crucible-CSRF':$('launch-task').dataset.csrf},
          body:JSON.stringify({case:taskCase})
        });
        if (response.status === 409) {
          showLaunchStatus('Another remote task is active', 'active');
          return;
        }
        if (response.status !== 202) throw new Error('launch rejected');
        const result = await response.json();
        const taskId = boundedText(result.task_id, 80);
        const jobId = boundedText(result.job_id, 80);
        if (!taskId && !jobId) throw new Error('missing task ID');
        currentJobId = jobId;
        brokerActive = true;
        resetTrajectory(taskId);
        taskActive = true;
        closedTaskId = '';
        closedJobId = '';
        setTrajectoryOpen(true);
        taskState('Queued on VM1; waiting for the live agent trajectory.');
        showLaunchStatus('Queued on VM1', 'active');
        loadTrajectorySnapshot();
      } catch (_) {
        showLaunchStatus('Launch failed · check the control plane', 'error');
      } finally {
        launchPending = false;
        loadTaskStatus();
      }
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
        if (taskActive && taskId && closedTaskId !== taskId && (!currentJobId || closedJobId !== currentJobId))
          setTrajectoryOpen(true);
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
      if (!open) { closedTaskId = currentTaskId; closedJobId = currentJobId; }
      else { closedTaskId = ''; closedJobId = ''; }
      setTrajectoryOpen(open);
    });
    $('close-trajectory').addEventListener('click', () => {
      closedTaskId = currentTaskId;
      closedJobId = currentJobId;
      setTrajectoryOpen(false);
      $('show-trajectory').focus();
    });
    $('launch-task').addEventListener('click', launchTask);
    loadTaskStatus(); setInterval(loadTaskStatus, 2500);
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


def _broker_call(socket_path: Path, request: dict) -> dict:
    payload = json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(payload) > 256:
        raise ValueError("broker request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(socket_path))
        connection.sendall(payload)
        with connection.makefile("rb") as response:
            raw = response.readline(1025)
    if not raw or len(raw) > 1024 or not raw.endswith(b"\n"):
        raise ValueError("invalid broker response")
    result = json.loads(raw)
    if not isinstance(result, dict) or result.get("ok") not in {True, False}:
        raise ValueError("invalid broker response")
    return result


def _public_task(value: object) -> dict:
    """Forward only the broker's closed, non-sensitive status fields."""
    if not isinstance(value, dict):
        raise ValueError("invalid broker task")
    job_id, task_id = value.get("job_id"), value.get("task_id")
    case, status, proof = value.get("case"), value.get("status"), value.get("proof_complete")
    completed = value.get("task_completed")
    if (job_id is not None and (not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id))
            or task_id is not None and (not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id))
            or case is not None and case not in _TASK_CASES
            or status not in _TASK_STATUSES
            or proof is not None and type(proof) is not bool
            or completed is not None and type(completed) is not bool):
        raise ValueError("invalid broker task")
    public = {"job_id": job_id, "task_id": task_id, "case": case,
              "status": status, "proof_complete": proof, "task_completed": completed}
    for key in ("started_at", "finished_at"):
        stamp = value.get(key)
        if stamp is not None and (not isinstance(stamp, str) or len(stamp) > 40 or
                                  not re.fullmatch(r"[0-9T:+.Z-]+", stamp)):
            raise ValueError("invalid broker timestamp")
        public[key] = stamp
    return public


def make_handler(db_path: Path, limit: int, *, task_socket: Path = DEFAULT_TASK_SOCKET) -> type[BaseHTTPRequestHandler]:
    stream_slots = threading.BoundedSemaphore(8)
    csrf_token = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def _loopback_host(self) -> str | None:
            hosts = self.headers.get_all("Host", [])
            if len(hosts) != 1:
                return None
            host = hosts[0]
            match = _LOOPBACK_HOST.fullmatch(host)
            if not match or (match.group(1) and int(match.group(1)) > 65535):
                return None
            try:
                if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                    return None
            except (ValueError, IndexError, TypeError):
                return None
            return host

        def do_GET(self) -> None:
            if self._loopback_host() is None:
                self._reply(403, "text/plain; charset=utf-8", b"forbidden\n")
                return
            parsed = urlsplit(self.path)
            route = parsed.path
            if route == "/":
                nonce = secrets.token_urlsafe(16)
                body = HTML.replace("__NONCE__", nonce).replace("__TASK_CSRF__", csrf_token).encode("utf-8")
                self._reply(200, "text/html; charset=utf-8", body,
                            csp=f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'")
            elif route == "/api/tasks/current":
                try:
                    result = _broker_call(task_socket, {"op": "current"})
                    if result.get("ok") is not True:
                        raise ValueError("broker status unavailable")
                    body = json.dumps(_public_task(result.get("task")), ensure_ascii=True).encode("ascii")
                except (OSError, ValueError, TypeError):
                    self._reply(503, "application/json", b'{"error":"task launcher unavailable"}')
                    return
                self._reply(200, "application/json", body)
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

        def do_POST(self) -> None:
            host = self._loopback_host()
            origins = self.headers.get_all("Origin", [])
            csrf_headers = self.headers.get_all("X-Crucible-CSRF", [])
            if host is None or len(origins) != 1 or origins[0] != "http://" + host:
                self._reply(403, "application/json", b'{"error":"forbidden"}')
                return
            if (len(csrf_headers) != 1 or len(csrf_headers[0]) != len(csrf_token)
                    or not csrf_headers[0].isascii()
                    or not hmac.compare_digest(csrf_headers[0], csrf_token)):
                self._reply(403, "application/json", b'{"error":"forbidden"}')
                return
            parsed = urlsplit(self.path)
            if parsed.path != "/api/tasks" or parsed.query or parsed.fragment:
                self._reply(404, "application/json", b'{"error":"not found"}')
                return
            if self.headers.get("Content-Type") != "application/json":
                self._reply(415, "application/json", b'{"error":"JSON required"}')
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or len(lengths[0]) > 3 or
                    not lengths[0].isascii() or not lengths[0].isdecimal()):
                self._reply(400, "application/json", b'{"error":"invalid request"}')
                return
            length = int(lengths[0])
            if not 1 <= length <= 128 or self.headers.get("Transfer-Encoding"):
                self._reply(400, "application/json", b'{"error":"invalid request"}')
                return
            def unique_object(pairs: list[tuple[str, object]]) -> dict:
                result: dict = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate key")
                    result[key] = value
                return result
            try:
                self.connection.settimeout(3)
                request = json.loads(self.rfile.read(length), object_pairs_hook=unique_object)
                if (not isinstance(request, dict) or set(request) != {"case"}
                        or not isinstance(request["case"], str) or request["case"] not in _TASK_CASES):
                    raise ValueError("invalid task case")
            except (ValueError, UnicodeError, TimeoutError, OSError):
                self._reply(400, "application/json", b'{"error":"invalid request"}')
                return
            try:
                result = _broker_call(task_socket, {"op": "start", "case": request["case"]})
                if result.get("ok") is True:
                    body = json.dumps(_public_task(result.get("task")), ensure_ascii=True).encode("ascii")
                    self._reply(202, "application/json", body)
                elif result.get("error") == "busy":
                    self._reply(409, "application/json", b'{"error":"task already active"}')
                else:
                    self._reply(503, "application/json", b'{"error":"task launcher unavailable"}')
            except (OSError, ValueError, TypeError):
                self._reply(503, "application/json", b'{"error":"task launcher unavailable"}')

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
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            if csp:
                self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            # Request URLs may contain attacker-controlled data; do not log them.
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Keyless CRUCIBLE task dashboard")
    parser.add_argument("--db", default="data/experience.sqlite", help="ExperienceBank SQLite path")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback)")
    parser.add_argument("--port", type=int, default=8787, help="TCP port (default: 8787)")
    parser.add_argument("--limit", type=int, default=200, help="maximum episodes shown (1–1000)")
    parser.add_argument("--task-socket", type=Path, default=DEFAULT_TASK_SOCKET,
                        help="private fixed-case task broker socket")
    args = parser.parse_args(argv)
    if not 1 <= args.limit <= 1000:
        parser.error("--limit must be from 1 to 1000")
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("dashboard must bind to loopback")
    with ThreadingHTTPServer((args.host, args.port),
                             make_handler(Path(args.db), args.limit, task_socket=args.task_socket)) as server:
        print(f"CRUCIBLE dashboard listening on http://{args.host}:{server.server_port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

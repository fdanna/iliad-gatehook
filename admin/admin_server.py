#!/usr/bin/env python3
import base64
import contextlib
import fcntl
import html
import json
import os
import re
import shutil
import tempfile
import time
from calendar import timegm
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


HOST = os.environ.get("ADMIN_HOST", "127.0.0.1")
PORT = int(os.environ.get("ADMIN_PORT", "18744"))
WHITELIST_PATH = Path(os.environ.get("WHITELIST_PATH", "/opt/gatehook/whitelist.txt"))
WHITELIST_TOGGLE_PATH = Path(
    os.environ.get("WHITELIST_TOGGLE_PATH", "/opt/gatehook/whitelist.enabled")
)
ACCESS_LOG_PATH = Path(os.environ.get("ACCESS_LOG_PATH", "/opt/gatehook/access.log"))
SYSTEM_LOG_PATH = Path(os.environ.get("SYSTEM_LOG_PATH", "/opt/gatehook/system.log"))
BACKUP_DIR = Path(os.environ.get("BACKUP_DIR", "/opt/gatehook/backups"))
METADATA_PATH = Path(os.environ.get("METADATA_PATH", "/opt/gatehook/whitelist_meta.json"))
LOCK_PATH = Path(os.environ.get("ADMIN_LOCK_PATH", "/opt/gatehook/.admin.lock"))
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
MAX_LOG_LINES = int(os.environ.get("MAX_LOG_LINES", "80"))
MAX_CALLER_LENGTH = int(os.environ.get("MAX_CALLER_LENGTH", "256"))
DEFAULT_SIP_DOMAIN = os.environ.get("DEFAULT_SIP_DOMAIN", "voip.iliad.it")
DEFAULT_SIP_SUFFIX = os.environ.get("DEFAULT_SIP_SUFFIX", ";user=phone")
ACCESS_LOG_LIMIT = int(os.environ.get("ACCESS_LOG_LIMIT", "60"))
ACCESS_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<status>accepted|rejected)\s+caller=(?P<caller>.*?)\s+reason="
)


COUNTRY_CODES = {
    "1": "United States/Canada",
    "7": "Russia/Kazakhstan",
    "20": "Egypt",
    "27": "South Africa",
    "30": "Greece",
    "31": "Netherlands",
    "32": "Belgium",
    "33": "France",
    "34": "Spain",
    "36": "Hungary",
    "39": "Italy",
    "40": "Romania",
    "41": "Switzerland",
    "43": "Austria",
    "44": "United Kingdom",
    "45": "Denmark",
    "46": "Sweden",
    "47": "Norway",
    "48": "Poland",
    "49": "Germany",
    "51": "Peru",
    "52": "Mexico",
    "53": "Cuba",
    "54": "Argentina",
    "55": "Brazil",
    "56": "Chile",
    "57": "Colombia",
    "58": "Venezuela",
    "60": "Malaysia",
    "61": "Australia",
    "62": "Indonesia",
    "63": "Philippines",
    "64": "New Zealand",
    "65": "Singapore",
    "66": "Thailand",
    "81": "Japan",
    "82": "South Korea",
    "84": "Vietnam",
    "86": "China",
    "90": "Turkey",
    "91": "India",
    "92": "Pakistan",
    "93": "Afghanistan",
    "94": "Sri Lanka",
    "95": "Myanmar",
    "98": "Iran",
    "212": "Morocco",
    "213": "Algeria",
    "216": "Tunisia",
    "218": "Libya",
    "351": "Portugal",
    "352": "Luxembourg",
    "353": "Ireland",
    "354": "Iceland",
    "355": "Albania",
    "356": "Malta",
    "357": "Cyprus",
    "358": "Finland",
    "359": "Bulgaria",
    "370": "Lithuania",
    "371": "Latvia",
    "372": "Estonia",
    "373": "Moldova",
    "374": "Armenia",
    "375": "Belarus",
    "376": "Andorra",
    "377": "Monaco",
    "378": "San Marino",
    "380": "Ukraine",
    "381": "Serbia",
    "385": "Croatia",
    "386": "Slovenia",
    "387": "Bosnia and Herzegovina",
    "389": "North Macedonia",
    "420": "Czech Republic",
    "421": "Slovakia",
    "423": "Liechtenstein",
}

COUNTRY_FLAGS = {
    "1": "🇺🇸",
    "7": "🇷🇺",
    "20": "🇪🇬",
    "27": "🇿🇦",
    "30": "🇬🇷",
    "31": "🇳🇱",
    "32": "🇧🇪",
    "33": "🇫🇷",
    "34": "🇪🇸",
    "36": "🇭🇺",
    "39": "🇮🇹",
    "40": "🇷🇴",
    "41": "🇨🇭",
    "43": "🇦🇹",
    "44": "🇬🇧",
    "45": "🇩🇰",
    "46": "🇸🇪",
    "47": "🇳🇴",
    "48": "🇵🇱",
    "49": "🇩🇪",
    "51": "🇵🇪",
    "52": "🇲🇽",
    "53": "🇨🇺",
    "54": "🇦🇷",
    "55": "🇧🇷",
    "56": "🇨🇱",
    "57": "🇨🇴",
    "58": "🇻🇪",
    "60": "🇲🇾",
    "61": "🇦🇺",
    "62": "🇮🇩",
    "63": "🇵🇭",
    "64": "🇳🇿",
    "65": "🇸🇬",
    "66": "🇹🇭",
    "81": "🇯🇵",
    "82": "🇰🇷",
    "84": "🇻🇳",
    "86": "🇨🇳",
    "90": "🇹🇷",
    "91": "🇮🇳",
    "92": "🇵🇰",
    "93": "🇦🇫",
    "94": "🇱🇰",
    "95": "🇲🇲",
    "98": "🇮🇷",
    "212": "🇲🇦",
    "213": "🇩🇿",
    "216": "🇹🇳",
    "218": "🇱🇾",
    "351": "🇵🇹",
    "352": "🇱🇺",
    "353": "🇮🇪",
    "354": "🇮🇸",
    "355": "🇦🇱",
    "356": "🇲🇹",
    "357": "🇨🇾",
    "358": "🇫🇮",
    "359": "🇧🇬",
    "370": "🇱🇹",
    "371": "🇱🇻",
    "372": "🇪🇪",
    "373": "🇲🇩",
    "374": "🇦🇲",
    "375": "🇧🇾",
    "376": "🇦🇩",
    "377": "🇲🇨",
    "378": "🇸🇲",
    "380": "🇺🇦",
    "381": "🇷🇸",
    "385": "🇭🇷",
    "386": "🇸🇮",
    "387": "🇧🇦",
    "389": "🇲🇰",
    "420": "🇨🇿",
    "421": "🇸🇰",
    "423": "🇱🇮",
}


HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gatehook Admin</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --panel-soft: #f1f4f7;
      --text: #17202a;
      --muted: #667281;
      --line: #d8dde4;
      --accent: #136f63;
      --accent-dark: #0f5a51;
      --danger: #b42318;
      --danger-soft: #fff1f0;
      --ok-soft: #eaf7f1;
      --shadow: 0 12px 28px rgba(20, 30, 40, 0.08);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-size: 14px;
      line-height: 1.45;
    }
    button, input, select {
      font: inherit;
    }
    button {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
      min-height: 36px;
      padding: 0 12px;
      cursor: pointer;
      font-weight: 650;
    }
    button:hover { border-color: #aeb8c4; }
    button.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }
    button.primary:hover { background: var(--accent-dark); }
    button.danger {
      color: var(--danger);
      border-color: #f0b8b2;
      background: #fff;
    }
    button:disabled {
      cursor: not-allowed;
      opacity: .55;
    }
    input, select {
      width: 100%;
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      padding: 0 10px;
      outline: none;
    }
    input:focus, select:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(19, 111, 99, 0.13);
    }
    .app {
      display: grid;
      grid-template-columns: 232px 1fr;
      min-height: 100vh;
    }
    aside {
      background: #111820;
      color: #eef3f6;
      padding: 24px 18px;
    }
    .brand {
      font-size: 18px;
      font-weight: 760;
      margin-bottom: 28px;
    }
    .status {
      display: grid;
      gap: 12px;
    }
    .status-item {
      border: 1px solid rgba(255,255,255,.12);
      border-radius: 8px;
      padding: 12px;
      background: rgba(255,255,255,.04);
    }
    .status-label {
      color: #aeb9c5;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .status-value {
      margin-top: 5px;
      font-size: 20px;
      font-weight: 750;
    }
    main {
      padding: 28px;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 18px;
    }
    .topbar-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .rome-clock {
      min-width: 205px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 8px 10px;
      text-align: right;
      box-shadow: 0 6px 18px rgba(20, 30, 40, 0.05);
    }
    .rome-clock-label {
      color: var(--muted);
      font-size: 11px;
      font-weight: 750;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    .rome-clock-value {
      margin-top: 2px;
      font-size: 14px;
      font-weight: 750;
      color: var(--text);
    }
    h1 {
      margin: 0;
      font-size: 28px;
      line-height: 1.15;
      letter-spacing: 0;
    }
    .subtle {
      color: var(--muted);
      margin-top: 5px;
    }
    .grid {
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(340px, .65fr);
      gap: 18px;
      align-items: start;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    .panel-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 15px 16px;
      border-bottom: 1px solid var(--line);
    }
    h2 {
      font-size: 16px;
      line-height: 1.25;
      margin: 0;
    }
    .panel-body {
      padding: 16px;
    }
    .form-grid {
      display: grid;
      grid-template-columns: 130px minmax(210px, 280px) auto;
      gap: 10px;
      align-items: start;
      margin-bottom: 14px;
    }
    .country-code-wrap {
      display: grid;
      gap: 5px;
    }
    .form-grid > label,
    .country-code-wrap {
      align-self: start;
    }
    .country-hint {
      min-height: 20px;
      color: var(--text);
      font-size: 13px;
      font-weight: 650;
      text-transform: none;
      letter-spacing: 0;
    }
    .phone-meta {
      min-height: 20px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 650;
      text-transform: none;
      letter-spacing: 0;
    }
    label {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }
    th, td {
      border-top: 1px solid var(--line);
      padding: 10px 8px;
      text-align: left;
      vertical-align: middle;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      font-weight: 750;
      text-transform: uppercase;
      letter-spacing: .04em;
    }
    td.caller {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      overflow-wrap: anywhere;
      font-size: 19px;
    }
    .country {
      width: 150px;
      font-size: 19px;
    }
    .added {
      width: 120px;
      font-size: 14px;
      color: var(--muted);
    }
    .actions {
      width: 94px;
      text-align: right;
    }
    .empty {
      color: var(--muted);
      padding: 22px 8px;
      text-align: center;
      border-top: 1px solid var(--line);
    }
    .switch-row, .backup-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }
    .switch {
      position: relative;
      width: 50px;
      height: 28px;
      border: 0;
      border-radius: 999px;
      background: #9aa5b1;
      padding: 0;
    }
    .switch::after {
      content: "";
      position: absolute;
      top: 4px;
      left: 4px;
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: #fff;
      transition: transform .16s ease;
    }
    .switch.on { background: var(--accent); }
    .switch.on::after { transform: translateX(22px); }
    .stack {
      display: grid;
      gap: 18px;
    }
    .logs {
      display: grid;
      gap: 10px;
    }
    .log-box {
      height: 210px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #0d1319;
      color: #d9e2ea;
      padding: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
      white-space: pre-wrap;
    }
    .access-table-wrap {
      max-height: 250px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
    }
    .access-table th,
    .access-table td {
      padding: 8px;
      font-size: 13px;
    }
    .access-phone {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      overflow-wrap: anywhere;
    }
    .access-result {
      width: 90px;
      font-weight: 750;
      text-transform: capitalize;
    }
    .access-result.accepted {
      color: var(--accent-dark);
    }
    .access-result.rejected {
      color: var(--danger);
    }
    .message {
      min-height: 20px;
      color: var(--muted);
    }
    .message.error { color: var(--danger); }
    .message.ok { color: var(--accent-dark); }
    @media (max-width: 920px) {
      .app { grid-template-columns: 1fr; }
      aside { display: none; }
      main { padding: 18px; }
      .topbar { align-items: flex-start; flex-direction: column; }
      .topbar-actions { width: 100%; justify-content: space-between; }
      .rome-clock { text-align: left; }
      .grid { grid-template-columns: 1fr; }
      .form-grid { grid-template-columns: 1fr; }
      .actions { width: 84px; }
    }
  </style>
</head>
<body>
  <div class="app">
    <aside>
      <div class="brand">Gatehook Admin</div>
      <div class="status">
        <div class="status-item">
          <div class="status-label">Whitelist</div>
          <div class="status-value" id="side-enabled">-</div>
        </div>
        <div class="status-item">
          <div class="status-label">Allowed Callers</div>
          <div class="status-value" id="side-count">0</div>
        </div>
        <div class="status-item">
          <div class="status-label">Backups</div>
          <div class="status-value" id="side-backups">0</div>
        </div>
      </div>
    </aside>
    <main>
      <div class="topbar">
        <div>
          <h1>Phone Whitelist</h1>
          <div class="subtle">Changes are written to the live-reloaded files. No gate service restart is required.</div>
        </div>
        <div class="topbar-actions">
          <div class="rome-clock">
            <div class="rome-clock-label">Rome Time</div>
            <div class="rome-clock-value" id="rome-clock">-</div>
          </div>
          <button id="refresh">Refresh</button>
        </div>
      </div>
      <div class="grid">
        <section class="panel">
          <div class="panel-head">
            <h2>Allowed Callers</h2>
            <div class="message" id="message"></div>
          </div>
          <div class="panel-body">
            <form class="form-grid" id="add-form">
              <div class="country-code-wrap">
                <label>
                  Country Code
                  <input id="country-code" name="country-code" autocomplete="off" inputmode="numeric" maxlength="3" value="39" placeholder="39">
                </label>
                <div class="country-hint" id="country-preview">🇮🇹 Italy</div>
              </div>
              <label>
                Phone Number
                <input id="phone-number" name="phone-number" autocomplete="off" inputmode="tel" maxlength="14" placeholder="3331234567">
                <span class="phone-meta" id="phone-meta">Up to 13 digits</span>
              </label>
              <button class="primary" type="submit">Add</button>
            </form>
            <table>
              <thead>
                <tr>
                  <th>Phone Number</th>
                  <th class="country">Country</th>
                  <th class="added">Added</th>
                  <th class="actions">Action</th>
                </tr>
              </thead>
              <tbody id="entries"></tbody>
            </table>
          </div>
        </section>
        <div class="stack">
          <section class="panel">
            <div class="panel-head"><h2>Whitelist Control</h2></div>
            <div class="panel-body switch-row">
              <div>
                <strong id="enabled-text">Loading</strong>
                <div class="subtle">Toggle writes whitelist.enabled atomically.</div>
              </div>
              <button class="switch" id="toggle" aria-label="Toggle whitelist"></button>
            </div>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Backups</h2></div>
            <div class="panel-body">
              <div class="backup-row">
                <select id="backup-select" aria-label="Backup"></select>
                <button id="download">Download</button>
                <button id="restore" class="danger">Restore</button>
              </div>
            </div>
          </section>
          <section class="panel">
            <div class="panel-head"><h2>Recent Logs</h2></div>
            <div class="panel-body logs">
              <label>Access Log</label>
              <div class="access-table-wrap">
                <table class="access-table">
                  <thead>
                    <tr>
                      <th>Date/Time (Rome)</th>
                      <th>Phone Number</th>
                      <th class="access-result">Result</th>
                    </tr>
                  </thead>
                  <tbody id="access-log"></tbody>
                </table>
              </div>
              <label>System Log</label>
              <div class="log-box" id="system-log"></div>
            </div>
          </section>
        </div>
      </div>
    </main>
  </div>
  <script>
    const qs = (id) => document.getElementById(id);
    const countryLookup = {
      "1": ["🇺🇸", "United States/Canada"],
      "7": ["🇷🇺", "Russia/Kazakhstan"],
      "20": ["🇪🇬", "Egypt"],
      "27": ["🇿🇦", "South Africa"],
      "30": ["🇬🇷", "Greece"],
      "31": ["🇳🇱", "Netherlands"],
      "32": ["🇧🇪", "Belgium"],
      "33": ["🇫🇷", "France"],
      "34": ["🇪🇸", "Spain"],
      "36": ["🇭🇺", "Hungary"],
      "39": ["🇮🇹", "Italy"],
      "40": ["🇷🇴", "Romania"],
      "41": ["🇨🇭", "Switzerland"],
      "43": ["🇦🇹", "Austria"],
      "44": ["🇬🇧", "United Kingdom"],
      "45": ["🇩🇰", "Denmark"],
      "46": ["🇸🇪", "Sweden"],
      "47": ["🇳🇴", "Norway"],
      "48": ["🇵🇱", "Poland"],
      "49": ["🇩🇪", "Germany"],
      "51": ["🇵🇪", "Peru"],
      "52": ["🇲🇽", "Mexico"],
      "53": ["🇨🇺", "Cuba"],
      "54": ["🇦🇷", "Argentina"],
      "55": ["🇧🇷", "Brazil"],
      "56": ["🇨🇱", "Chile"],
      "57": ["🇨🇴", "Colombia"],
      "58": ["🇻🇪", "Venezuela"],
      "60": ["🇲🇾", "Malaysia"],
      "61": ["🇦🇺", "Australia"],
      "62": ["🇮🇩", "Indonesia"],
      "63": ["🇵🇭", "Philippines"],
      "64": ["🇳🇿", "New Zealand"],
      "65": ["🇸🇬", "Singapore"],
      "66": ["🇹🇭", "Thailand"],
      "81": ["🇯🇵", "Japan"],
      "82": ["🇰🇷", "South Korea"],
      "84": ["🇻🇳", "Vietnam"],
      "86": ["🇨🇳", "China"],
      "90": ["🇹🇷", "Turkey"],
      "91": ["🇮🇳", "India"],
      "92": ["🇵🇰", "Pakistan"],
      "93": ["🇦🇫", "Afghanistan"],
      "94": ["🇱🇰", "Sri Lanka"],
      "95": ["🇲🇲", "Myanmar"],
      "98": ["🇮🇷", "Iran"],
      "212": ["🇲🇦", "Morocco"],
      "213": ["🇩🇿", "Algeria"],
      "216": ["🇹🇳", "Tunisia"],
      "218": ["🇱🇾", "Libya"],
      "351": ["🇵🇹", "Portugal"],
      "352": ["🇱🇺", "Luxembourg"],
      "353": ["🇮🇪", "Ireland"],
      "354": ["🇮🇸", "Iceland"],
      "355": ["🇦🇱", "Albania"],
      "356": ["🇲🇹", "Malta"],
      "357": ["🇨🇾", "Cyprus"],
      "358": ["🇫🇮", "Finland"],
      "359": ["🇧🇬", "Bulgaria"],
      "370": ["🇱🇹", "Lithuania"],
      "371": ["🇱🇻", "Latvia"],
      "372": ["🇪🇪", "Estonia"],
      "373": ["🇲🇩", "Moldova"],
      "374": ["🇦🇲", "Armenia"],
      "375": ["🇧🇾", "Belarus"],
      "376": ["🇦🇩", "Andorra"],
      "377": ["🇲🇨", "Monaco"],
      "378": ["🇸🇲", "San Marino"],
      "380": ["🇺🇦", "Ukraine"],
      "381": ["🇷🇸", "Serbia"],
      "385": ["🇭🇷", "Croatia"],
      "386": ["🇸🇮", "Slovenia"],
      "387": ["🇧🇦", "Bosnia and Herzegovina"],
      "389": ["🇲🇰", "North Macedonia"],
      "420": ["🇨🇿", "Czech Republic"],
      "421": ["🇸🇰", "Slovakia"],
      "423": ["🇱🇮", "Liechtenstein"]
    };
    let state = null;
    const romeFormatter = new Intl.DateTimeFormat("en-GB", {
      timeZone: "Europe/Rome",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    });
    const romeLogFormatter = new Intl.DateTimeFormat("en-GB", {
      timeZone: "Europe/Rome",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false
    });

    function cleanDigits(value) {
      return String(value || "").replace(/\\D/g, "");
    }

    function parseLogTimestamp(value) {
      const normalized = String(value || "").replace(/([+-]\\d{2})(\\d{2})$/, "$1:$2");
      const parsed = new Date(normalized);
      return Number.isNaN(parsed.getTime()) ? null : parsed;
    }

    function formatRomeLogTime(value) {
      const parsed = parseLogTimestamp(value);
      return parsed ? romeLogFormatter.format(parsed).replace(",", "") : value;
    }

    function updateRomeClock() {
      qs("rome-clock").textContent = romeFormatter.format(new Date()).replace(",", "");
    }

    function countryCodeForSubmit() {
      return cleanDigits(qs("country-code").value) || "39";
    }

    function updateCountryPreview({ defaultEmpty = false } = {}) {
      let code = cleanDigits(qs("country-code").value).slice(0, 3);
      const codeFocused = document.activeElement === qs("country-code");
      if (!code && defaultEmpty && !codeFocused) code = "39";
      qs("country-code").value = code;
      const phone = qs("phone-number");
      const phoneMeta = qs("phone-meta");
      if (!code) {
        qs("country-preview").textContent = "";
        phone.maxLength = 14;
        phoneMeta.textContent = "Country code required";
        return code;
      }
      const match = countryLookup[code];
      const nationalMax = Math.max(1, 15 - code.length);
      phone.maxLength = String(nationalMax);
      phoneMeta.textContent = `Up to ${nationalMax} digits`;
      qs("country-preview").textContent = match ? `${match[0]} ${match[1]}` : "Unknown country";
      return code;
    }

    function buildCallerInput() {
      const code = countryCodeForSubmit();
      qs("country-code").value = code;
      updateCountryPreview({ defaultEmpty: true });
      const national = cleanDigits(qs("phone-number").value);
      if (!national) return "";
      if (code === "39") return national;
      return `00${code}${national}`;
    }

    function setMessage(text, kind = "") {
      const el = qs("message");
      el.className = `message ${kind}`;
      el.textContent = text;
      if (text) setTimeout(() => { if (el.textContent === text) el.textContent = ""; }, 4500);
    }

    async function api(path, options = {}) {
      const res = await fetch(path, {
        headers: { "Content-Type": "application/json" },
        ...options
      });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(payload.error || `Request failed: ${res.status}`);
      return payload;
    }

    function render(next) {
      state = next;
      qs("side-enabled").textContent = state.whitelist_enabled ? "On" : "Off";
      qs("side-count").textContent = state.entries.length;
      qs("side-backups").textContent = state.backups.length;
      qs("enabled-text").textContent = state.whitelist_enabled ? "Whitelist enabled" : "Whitelist disabled";
      qs("toggle").classList.toggle("on", state.whitelist_enabled);
      qs("toggle").setAttribute("aria-pressed", state.whitelist_enabled ? "true" : "false");

      const tbody = qs("entries");
      tbody.innerHTML = "";
      if (!state.entries.length) {
        tbody.innerHTML = `<tr><td class="empty" colspan="4">No active caller IDs are listed.</td></tr>`;
      } else {
        for (const entry of state.entries) {
          const raw = typeof entry === "string" ? entry : entry.raw;
          const display = typeof entry === "string" ? entry : entry.display;
          const entryCountry = typeof entry === "string" ? "" : entry.country;
          const addedText = typeof entry === "string" ? "Unknown" : entry.added;
          const tr = document.createElement("tr");
          const caller = document.createElement("td");
          caller.className = "caller";
          caller.textContent = display;
          const country = document.createElement("td");
          country.className = "country";
          country.textContent = entryCountry;
          const added = document.createElement("td");
          added.className = "added";
          added.textContent = addedText;
          const action = document.createElement("td");
          action.className = "actions";
          const btn = document.createElement("button");
          btn.className = "danger";
          btn.type = "button";
          btn.textContent = "Remove";
          btn.addEventListener("click", () => removeCaller(raw, display));
          action.appendChild(btn);
          tr.append(caller, country, added, action);
          tbody.appendChild(tr);
        }
      }

      const select = qs("backup-select");
      select.innerHTML = "";
      if (!state.backups.length) {
        const option = document.createElement("option");
        option.value = "";
        option.textContent = "No backups yet";
        select.appendChild(option);
      } else {
        for (const backup of state.backups) {
          const option = document.createElement("option");
          option.value = backup.name;
          option.textContent = `${backup.name} (${backup.size} bytes)`;
          select.appendChild(option);
        }
      }
      qs("restore").disabled = !state.backups.length;
      qs("download").disabled = !state.backups.length;
      const accessBody = qs("access-log");
      accessBody.innerHTML = "";
      if (!state.access_entries.length) {
        accessBody.innerHTML = `<tr><td class="empty" colspan="3">No access log entries yet.</td></tr>`;
      } else {
        for (const item of state.access_entries) {
          const tr = document.createElement("tr");
          const at = document.createElement("td");
          at.textContent = formatRomeLogTime(item.timestamp || item.display_time);
          const phone = document.createElement("td");
          phone.className = "access-phone";
          phone.textContent = item.phone;
          const result = document.createElement("td");
          result.className = `access-result ${item.result}`;
          result.textContent = item.result;
          tr.append(at, phone, result);
          accessBody.appendChild(tr);
        }
      }
      qs("system-log").textContent = state.logs.system || "No system log entries yet.";
    }

    async function refresh() {
      try {
        render(await api("/api/state"));
      } catch (err) {
        setMessage(err.message, "error");
      }
    }

    async function removeCaller(caller, display) {
      if (!confirm(`Remove ${display || caller}?`)) return;
      try {
        render(await api("/api/remove", { method: "POST", body: JSON.stringify({ caller }) }));
        setMessage("Caller removed. Backup created.", "ok");
      } catch (err) {
        setMessage(err.message, "error");
      }
    }

    qs("add-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const caller = buildCallerInput();
      try {
        render(await api("/api/add", { method: "POST", body: JSON.stringify({ caller }) }));
        qs("phone-number").value = "";
        qs("country-code").value = "39";
        updateCountryPreview({ defaultEmpty: true });
        setMessage("Caller added. Backup created.", "ok");
      } catch (err) {
        setMessage(err.message, "error");
      }
    });

    qs("country-code").addEventListener("focus", () => qs("country-code").select());
    qs("country-code").addEventListener("input", updateCountryPreview);
    qs("country-code").addEventListener("blur", () => {
      if (!cleanDigits(qs("country-code").value)) qs("country-code").value = "39";
      updateCountryPreview({ defaultEmpty: true });
    });
    qs("phone-number").addEventListener("focus", updateCountryPreview);
    updateCountryPreview({ defaultEmpty: true });

    qs("toggle").addEventListener("click", async () => {
      try {
        render(await api("/api/toggle", {
          method: "POST",
          body: JSON.stringify({ enabled: !state.whitelist_enabled })
        }));
        setMessage("Whitelist toggle updated. Backup created.", "ok");
      } catch (err) {
        setMessage(err.message, "error");
      }
    });

    qs("restore").addEventListener("click", async () => {
      const backup = qs("backup-select").value;
      if (!backup || !confirm(`Restore ${backup}?`)) return;
      try {
        render(await api("/api/restore", { method: "POST", body: JSON.stringify({ backup }) }));
        setMessage("Backup restored.", "ok");
      } catch (err) {
        setMessage(err.message, "error");
      }
    });

    qs("download").addEventListener("click", () => {
      const backup = qs("backup-select").value;
      if (backup) window.location.href = `/api/download?backup=${encodeURIComponent(backup)}`;
    });

    qs("refresh").addEventListener("click", refresh);
    updateRomeClock();
    setInterval(updateRomeClock, 1000);
    refresh();
  </script>
</body>
</html>
"""


def timestamp():
    return f"{time.strftime('%Y%m%dT%H%M%S%z')}.{time.time_ns()}"


def parse_bool_file(path):
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        return line.lower() in {"1", "true", "yes", "on", "enable", "enabled"}
    return False


def read_lines(path):
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []


def active_entries(lines):
    entries = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("<<<<<<<", "=======", ">>>>>>>")):
            continue
        entries.append(line)
    return entries


def phone_from_caller(caller):
    value = str(caller or "").strip()
    if value.startswith("sip:"):
        value = value[4:]
    value = value.split(";", 1)[0]
    if "@" in value:
        value = value.split("@", 1)[0]
    return value


def country_info_for_phone(phone):
    value = phone.strip()
    if value.startswith("+"):
        digits = value[1:]
    elif value.startswith("00"):
        digits = value[2:]
    else:
        return {"code": "39", "country": "Italy", "flag": COUNTRY_FLAGS.get("39", "")}

    for length in (3, 2, 1):
        prefix = digits[:length]
        if prefix in COUNTRY_CODES:
            return {
                "code": prefix,
                "country": COUNTRY_CODES[prefix],
                "flag": COUNTRY_FLAGS.get(prefix, ""),
            }
    return {"code": "", "country": "Unknown", "flag": ""}


def format_display_phone(phone):
    value = phone.strip()
    info = country_info_for_phone(value)
    if value.startswith("+"):
        digits = value[1:]
    elif value.startswith("00"):
        digits = value[2:]
    else:
        digits = value

    code = info["code"]
    if code and digits.startswith(code):
        national = digits[len(code) :]
    else:
        national = digits
    return f"+{code} {national}" if code else value


def entry_payload(caller):
    phone = phone_from_caller(caller)
    country = country_info_for_phone(phone)
    country_display = f"{country['flag']} {country['country']}".strip()
    return {
        "raw": caller,
        "display": format_display_phone(phone),
        "country": country_display,
        "added": added_label(caller),
    }


def normalize_caller_input(caller):
    value = validate_caller(caller)
    if value.startswith("sip:") or "@" in value:
        return value
    return f"sip:{value}@{DEFAULT_SIP_DOMAIN}{DEFAULT_SIP_SUFFIX}"


def validate_caller(caller):
    value = str(caller or "").strip()
    if not value:
        raise ValueError("Caller ID is required.")
    if len(value) > MAX_CALLER_LENGTH:
        raise ValueError(f"Caller ID must be {MAX_CALLER_LENGTH} characters or fewer.")
    if any(ord(ch) < 32 for ch in value):
        raise ValueError("Caller ID cannot contain control characters.")
    if value.startswith("#"):
        raise ValueError("Caller ID cannot start with #.")
    return value


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_stat = None
    with contextlib.suppress(FileNotFoundError):
        existing_stat = path.stat()
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            if existing_stat is not None:
                with contextlib.suppress(OSError):
                    os.fchmod(handle.fileno(), existing_stat.st_mode)
                with contextlib.suppress(OSError):
                    os.fchown(handle.fileno(), existing_stat.st_uid, existing_stat.st_gid)
            else:
                with contextlib.suppress(OSError):
                    parent_stat = path.parent.stat()
                    os.fchmod(handle.fileno(), 0o664)
                    os.fchown(handle.fileno(), parent_stat.st_uid, parent_stat.st_gid)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        with contextlib.suppress(OSError):
            dir_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)
        raise


def backup_path(source):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return BACKUP_DIR / f"{source.name}.{timestamp()}.bak"


def create_backup(source):
    if not source.exists():
        return None
    destination = backup_path(source)
    shutil.copy2(source, destination)
    return destination


def utc_now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_metadata():
    try:
        payload = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    entries = payload.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def write_metadata(entries):
    payload = json.dumps({"entries": entries}, indent=2, sort_keys=True)
    atomic_write(METADATA_PATH, payload + "\n")


def added_label(caller):
    entry = load_metadata().get(caller, {})
    if not isinstance(entry, dict):
        return "Unknown"
    added_at = entry.get("added_at")
    if not added_at:
        return "Unknown"
    try:
        added_ts = time.strptime(added_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return "Unknown"
    added_seconds = timegm(added_ts)
    days = max(0, int((time.time() - added_seconds) // 86400))
    if days == 0:
        return "Today"
    if days == 1:
        return "1 day ago"
    return f"{days} days ago"


def mark_added(caller):
    metadata = load_metadata()
    existing = metadata.get(caller, {})
    if not isinstance(existing, dict):
        existing = {}
    existing.setdefault("added_at", utc_now_iso())
    metadata[caller] = existing
    write_metadata(metadata)


def remove_metadata(caller):
    metadata = load_metadata()
    if caller in metadata:
        metadata.pop(caller, None)
        write_metadata(metadata)


def reconcile_metadata(active_callers):
    metadata_exists = METADATA_PATH.exists()
    metadata = load_metadata()
    changed = False

    for caller in active_callers:
        if caller in metadata:
            continue
        metadata[caller] = {"added_at": utc_now_iso() if metadata_exists else None}
        changed = True

    if changed or not metadata_exists:
        write_metadata(metadata)


@contextlib.contextmanager
def write_lock():
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def tail(path, max_lines):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return ""
    return "\n".join(lines[-max_lines:])


def access_display_time(timestamp_value):
    try:
        parsed = time.strptime(timestamp_value, "%Y-%m-%dT%H:%M:%S%z")
        return time.strftime("%Y-%m-%d %H:%M", parsed)
    except ValueError:
        return timestamp_value


def parse_access_log(path, limit):
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return []

    entries = []
    for raw in lines:
        match = ACCESS_LINE_RE.match(raw.strip())
        if not match:
            continue
        caller = match.group("caller")
        entries.append(
            {
                "timestamp": match.group("ts"),
                "display_time": access_display_time(match.group("ts")),
                "phone": format_display_phone(phone_from_caller(caller)),
                "result": match.group("status"),
            }
        )
    return sorted(entries, key=lambda item: item["timestamp"], reverse=True)[:limit]


def list_backups():
    if not BACKUP_DIR.exists():
        return []
    backups = []
    for item in BACKUP_DIR.iterdir():
        if not item.is_file() or not item.name.startswith("whitelist.txt."):
            continue
        stat = item.stat()
        backups.append(
            {
                "name": item.name,
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
            }
        )
    return sorted(backups, key=lambda item: item["mtime"], reverse=True)


def state():
    lines = read_lines(WHITELIST_PATH)
    entries = active_entries(lines)
    reconcile_metadata(entries)
    return {
        "whitelist_enabled": parse_bool_file(WHITELIST_TOGGLE_PATH),
        "entries": [entry_payload(entry) for entry in entries],
        "backups": list_backups(),
        "access_entries": parse_access_log(ACCESS_LOG_PATH, ACCESS_LOG_LIMIT),
        "logs": {
            "system": tail(SYSTEM_LOG_PATH, MAX_LOG_LINES),
        },
    }


def add_caller(caller):
    caller = normalize_caller_input(caller)
    with write_lock():
        lines = read_lines(WHITELIST_PATH)
        entries = active_entries(lines)
        if caller in entries:
            raise ValueError("Caller ID is already present.")
        create_backup(WHITELIST_PATH)
        if lines and lines[-1].strip():
            lines.append(caller)
        else:
            lines = lines + [caller]
        atomic_write(WHITELIST_PATH, "\n".join(lines).rstrip() + "\n")
        mark_added(caller)
    return state()


def remove_caller(caller):
    caller = validate_caller(caller)
    with write_lock():
        lines = read_lines(WHITELIST_PATH)
        next_lines = [line for line in lines if line.strip() != caller]
        if len(next_lines) == len(lines):
            raise ValueError("Caller ID was not found.")
        create_backup(WHITELIST_PATH)
        atomic_write(WHITELIST_PATH, "\n".join(next_lines).rstrip() + "\n")
        remove_metadata(caller)
    return state()


def set_toggle(enabled):
    with write_lock():
        create_backup(WHITELIST_TOGGLE_PATH)
        atomic_write(WHITELIST_TOGGLE_PATH, "1\n" if enabled else "0\n")
    return state()


def restore_backup(name):
    if not name or "/" in name or name.startswith("."):
        raise ValueError("Invalid backup name.")
    source = BACKUP_DIR / name
    if not source.exists() or not source.is_file() or not source.name.startswith("whitelist.txt."):
        raise ValueError("Backup was not found.")
    with write_lock():
        create_backup(WHITELIST_PATH)
        content = source.read_text(encoding="utf-8")
        atomic_write(WHITELIST_PATH, content if content.endswith("\n") else content + "\n")
    return state()


class Handler(BaseHTTPRequestHandler):
    server_version = "GatehookAdmin/1.0"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return self.send_json({"ok": True})
        if not self.authorized():
            return self.send_auth_required()
        if parsed.path == "/":
            return self.send_html(HTML)
        if parsed.path == "/api/state":
            return self.send_json(state())
        if parsed.path == "/api/download":
            params = parse_qs(parsed.query)
            backup = params.get("backup", [""])[0]
            return self.download_backup(backup)
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        if not self.authorized():
            return self.send_auth_required()
        try:
            payload = self.read_json()
            if self.path == "/api/add":
                return self.send_json(add_caller(payload.get("caller")))
            if self.path == "/api/remove":
                return self.send_json(remove_caller(payload.get("caller")))
            if self.path == "/api/toggle":
                return self.send_json(set_toggle(bool(payload.get("enabled"))))
            if self.path == "/api/restore":
                return self.send_json(restore_backup(payload.get("backup")))
            self.send_error(HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except OSError as exc:
            self.send_json({"error": f"File operation failed: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON payload.") from exc

    def send_html(self, text):
        body = text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        if not ADMIN_USERNAME and not ADMIN_PASSWORD:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header[6:]).decode("utf-8")
        except Exception:
            return False
        username, _, password = decoded.partition(":")
        return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

    def send_auth_required(self):
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Gatehook Admin"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def download_backup(self, name):
        if not name or "/" in name or name.startswith("."):
            return self.send_json({"error": "Invalid backup name."}, HTTPStatus.BAD_REQUEST)
        path = BACKUP_DIR / name
        if not path.exists() or not path.is_file() or not path.name.startswith("whitelist.txt."):
            return self.send_json({"error": "Backup was not found."}, HTTPStatus.NOT_FOUND)
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{html.escape(path.name)}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"gatehook admin listening on http://{HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

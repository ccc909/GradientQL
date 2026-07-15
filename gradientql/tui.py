"""Textual TUI: the GradientQL logo, a menu with settings, and a live scan dashboard."""

from __future__ import annotations

import copy
import os
import pathlib
import queue
import time
from typing import Any

from rich.style import Style
from rich.text import Span, Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Center, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.theme import Theme
from textual.validation import Integer, Number
from textual.widgets import (
    Button, DataTable, Footer, Input, Label, ProgressBar, RichLog, Static, Switch,
)

from .scanner import coverage, memory

GOLD = "#e8a317"
GOLD_HI = "#ffcf5c"
_LOGO = pathlib.Path(__file__).with_name("assets") / "logo.ans"

_THEME = Theme(
    name="gradientql",
    primary=GOLD,
    secondary="#b9770c",
    accent=GOLD_HI,
    warning=GOLD,
    error="#d75f5f",
    success=GOLD,
    foreground="#ece0c8",
    background="#100e0a",
    surface="#1b1712",
    panel="#241f17",
    dark=True,
)

_GLYPH: dict[str, tuple[str, str]] = {
    "untested": (".", "grey42"),
    "shallow": ("o", "yellow"),
    "open": ("?", "cyan"),
    "data": ("+", "green"),
    "dead": ("x", "grey37"),
    "finding": ("!", "bold red"),
    "exploited": ("*", "bold magenta"),
}

_ATTACK_DEFAULTS = [("injection", True), ("ssrf", True), ("dos", False), ("smuggle", True),
                    ("csrf", True), ("jwt", True), ("brute", True), ("bola", True)]

_ATTACK_LABELS = {
    "injection": "injection: SQLi, command, template",
    "ssrf": "ssrf: server-side request forgery",
    "dos": "dos: resource exhaustion (can crash a target)",
    "smuggle": "smuggle: request smuggling",
    "csrf": "csrf: cross-site request forgery",
    "jwt": "jwt: token forging, weak secrets",
    "brute": "brute: credential / coupon brute-force",
    "bola": "bola: broken object-level auth (IDOR)",
}


def _strip_bg(style: Any) -> Any:
    if not isinstance(style, Style):
        return style
    return Style(color=style.color, bold=style.bold, dim=style.dim)


def _logo_text() -> Text:
    try:
        t = Text.from_ansi(_LOGO.read_text(encoding="utf-8").rstrip("\n"))
        t.spans = [Span(s.start, s.end, _strip_bg(s.style)) for s in t.spans]
        return t
    except Exception:  # noqa: BLE001
        return Text("G R A D I E N T Q L", style=f"bold {GOLD}")


def _field_state(entry: dict | None) -> str:
    if not entry or not (entry.get("attempts") or entry.get("auto") or entry.get("finding")):
        return "untested"
    st = memory.effective_state(entry)
    if st in ("finding", "exploited", "data", "open"):
        return st
    return "dead" if coverage._attacked(entry) else "shallow"


def _root_fields(sm: dict[str, Any], key: str) -> list[str]:
    root = sm.get(sm.get(key, ""))
    return [f for f in root if not str(f).startswith("_")] if isinstance(root, dict) else []


def coverage_text(ctx: Any) -> Text:
    if ctx is None:
        return Text("waiting for the schema...", style="dim")
    sm, ledger = ctx.schema_map, ctx.ledger
    q, m = _root_fields(sm, "_query_type"), _root_fields(sm, "_mutation_type")

    def probed(fs: list[str]) -> int:
        return sum(1 for f in fs if _field_state(ledger.get(f)) != "untested")

    t = Text()
    hv = coverage.high_value_targets(sm)
    if hv:
        t.append("high-value targets\n", style="bold #ffcf5c")
        for label, info in sorted(hv.items(), key=lambda kv: kv[1]["rank"])[:6]:
            t.append(f"  {label}: ", style="grey54")
            for f in info["fields"][:6]:
                g, st = _GLYPH[_field_state(ledger.get(f))]
                t.append(f"{g} {f}  ", style=st)
            t.append("\n")
        t.append("\n")
    for name, fields in (("Query", q), ("Mutation", m)):
        if not fields:
            continue
        t.append(f"{name}  {probed(fields)}/{len(fields)}\n", style=f"bold {GOLD}")
        for f in fields:
            g, st = _GLYPH[_field_state(ledger.get(f))]
            t.append(g + " ", style=st)
        t.append("\n\n")
    t.append(". untested   o probed   ? auth-gated\n+ data   x exhausted   ! finding", style="dim")
    return t


def loot_text(ctx: Any) -> Text:
    if ctx is None:
        return Text("waiting...", style="dim")
    t = Text()
    creds = getattr(ctx, "credentials", None) or []
    if creds:
        t.append("credentials\n", style=f"bold {GOLD_HI}")
        for c in creds[-6:]:
            who = next((f"{k}={v}" for k, v in c.items() if k != "password"), "?")
            t.append(f"  {who}", style="green")
            if c.get("password"):
                t.append(f" : {c['password']}", style="grey54")
            t.append("\n")
        t.append("\n")
    ident = getattr(ctx, "identity", None) or {}
    tok = next((v for k, v in ident.items()
                if any(x in k.lower() for x in ("auth", "token", "cookie", "session", "bearer", "key"))), None)
    if tok:
        t.append("session\n", style=f"bold {GOLD_HI}")
        t.append(f"  {str(tok)[:56]}\n\n", style="cyan")
    harv = [(k, v) for k, v in (getattr(ctx, "harvested", None) or {}).items() if v]
    if harv:
        t.append("harvested\n", style=f"bold {GOLD_HI}")
        for cat, vals in harv[:6]:
            t.append(f"  {cat} ({len(vals)}): ", style="grey54")
            t.append(", ".join(str(v)[:18] for v in vals[:3]), style="cyan")
            t.append("\n")
        t.append("\n")
    facts = getattr(ctx, "facts", None) or []
    if facts:
        t.append("knowledge\n", style=f"bold {GOLD_HI}")
        for f in facts[-5:]:
            t.append(f"  - {str(f)[:62]}\n", style="grey62")
    if not len(t):
        t.append("no loot yet", style="dim")
    return t


ERR_RED = "#d75f5f"
OK_GREEN = "#7bc47f"

_A_ERR = ("error", "failed", "circuit open", "abort", "rejected", "timed out", "cannot",
          "refus", "unreachable", "no auth credentials", " 5xx", "http 5")
_A_HIT = ("confirmed", "rce", "injection", "bola", "bfla", "ssrf", "idor", "leaked", "minted",
          "exposed", "exfil", "finding", "vuln", "token mint", "dumped", "smuggl", "traversal")
_A_WIN = ("authenticated", "logged in", "registered", "harvested", "-> data", "obtained", "granted")
_A_LOW = ("null", "empty", "dead", "no data", "blocked", "auth-blocked", "http403", "http401",
          " 403", " 401", "no change", "skip")


def _activity_text(line: str) -> Text:
    low = line.lower()
    if any(k in low for k in _A_ERR):
        return Text("x " + line, style=f"bold {ERR_RED}")
    if any(k in low for k in _A_HIT):
        return Text("! " + line, style=f"bold {GOLD_HI}")
    if any(k in low for k in _A_WIN):
        return Text("+ " + line, style=OK_GREEN)
    if any(k in low for k in _A_LOW):
        return Text("- " + line, style="grey50")
    return Text("  " + line, style="grey82")


def _has_key(settings: dict[str, Any]) -> bool:
    llm = settings.get("llm", {})
    if llm.get("api_key"):
        return True
    return bool(os.environ.get(llm.get("api_key_env", "OPENROUTER_API_KEY")))


class MenuScreen(Screen):
    BINDINGS = [("s", "start", "Start scan"), ("r", "resume", "Resume last"),
                ("g", "settings", "Settings"), ("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        with Center(id="logo_row"):
            yield Static(id="logo")
        with Center(id="menu_row"):
            with Vertical(id="menu"):
                yield Button("START SCAN", id="start", variant="primary")
                yield Button("RESUME LAST", id="resume")
                yield Button("SETTINGS", id="settings")
                yield Button("QUIT", id="quit")
                yield Static(id="summary", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self._set_logo()
        menu = self.query_one("#menu")
        menu.border_title = "MAIN MENU"
        menu.border_subtitle = "▓▒░"  # ▓▒░ retro fade
        self._refresh()

    def on_resize(self) -> None:
        self._set_logo()

    def on_screen_resume(self) -> None:
        self._refresh()

    def _set_logo(self) -> None:
        wide = self.app.size.width >= 128
        self.query_one("#logo", Static).update(
            _logo_text() if wide else Text("G R A D I E N T Q L", style=f"bold {GOLD}"))

    def _refresh(self) -> None:
        s = self.app.settings
        url = s.get("target", {}).get("url") or "not set"
        b = s.get("scanner", {}).get("budget", 60)
        model = s.get("llm", {}).get("attacker_model", "?")
        proxy = s.get("http", {}).get("proxy") or "direct"
        safe = "on" if s.get("scanner", {}).get("safe_mode") else "off"
        maxtok = s.get("llm", {}).get("attacker_max_tokens", "?")
        ckpt = "on" if s.get("scanner", {}).get("checkpoint", {}).get("enabled") else "off"
        key = "set" if _has_key(s) else "NOT SET (config/api_key.local or OPENROUTER_API_KEY)"
        self.query_one("#summary", Static).update(
            f"TARGET   {url}\nBUDGET   {b} steps    MODEL  {model}\n"
            f"PROXY    {proxy}    SAFE MODE  {safe}\nMAX TOK  {maxtok}    CHECKPOINT  {ckpt}\n"
            f"API KEY  {key}")

    def action_quit(self) -> None:
        self.app.exit()

    def action_settings(self) -> None:
        self.app.push_screen(SettingsScreen())

    def action_start(self) -> None:
        if getattr(self.app, "scan_active", False):
            self.notify("A scan is still finishing. Try again in a moment.", severity="warning")
            return
        s = self.app.settings
        if not s.get("target", {}).get("url", "").strip():
            self.notify("Set a target in Settings first.", severity="warning")
            self.app.push_screen(SettingsScreen())
        elif not _has_key(s):
            env = s.get("llm", {}).get("api_key_env", "OPENROUTER_API_KEY")
            self.notify(f"No API key. Set {env} or config/api_key.local.", severity="error")
        else:
            self.app.push_screen(DashboardScreen())

    def action_resume(self) -> None:
        if getattr(self.app, "scan_active", False):
            self.notify("A scan is still finishing. Try again in a moment.", severity="warning")
            return
        from .scanner import checkpoint as _cp
        s = self.app.settings
        cpf = _cp.latest(s)
        if cpf is None:
            self.notify("No saved runs to resume (output/checkpoints is empty).", severity="warning")
            return
        if not _has_key(s):
            env = s.get("llm", {}).get("api_key_env", "OPENROUTER_API_KEY")
            self.notify(f"No API key. Set {env} or config/api_key.local.", severity="error")
            return
        try:
            data = _cp.load(cpf)
        except (ValueError, OSError) as e:  # JSONDecodeError is a ValueError
            self.notify(f"Checkpoint is unreadable: {str(e)[:60]}", severity="error")
            return
        self.app.target = data.get("target_url") or self.app.target
        self.app.push_screen(DashboardScreen(resume=data))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "quit":
            self.action_quit()
        elif event.button.id == "settings":
            self.action_settings()
        elif event.button.id == "resume":
            self.action_resume()
        elif event.button.id == "start":
            self.action_start()


class SettingsScreen(Screen):
    BINDINGS = [("escape", "back", "Back")]

    _FIELDS = [
        ("url", "target url", "target", "url", str),
        ("budget", "budget (steps)", "scanner", "budget", int),
        ("model", "model", "llm", "attacker_model", str),
        ("proxy", "proxy (http://host:port)", "http", "proxy", str),
        ("delay", "request delay (s)", "http", "delay", float),
        ("timeout", "request timeout (s)", "http", "timeout", int),
        ("fuzz", "fuzz max payloads", "scanner", "fuzz.max_payloads", int),
    ]
    _SWITCHES = [
        ("verify_tls", "verify TLS", "http", "verify_tls", True),
        ("safe_mode", "safe mode (disable destructive)", "scanner", "safe_mode", False),
    ]
    _MIN = {"budget": 1, "delay": 0.0, "timeout": 1, "fuzz": 1}

    def compose(self) -> ComposeResult:
        s = self.app.settings
        yield Static("GRADIENTQL   settings", id="title")
        with VerticalScroll(id="form"):
            for wid, label, sect, key, typ in self._FIELDS:
                yield Label(label)
                if typ is int:
                    v: Any = [Integer(minimum=self._MIN.get(wid, 0))]
                elif typ is float:
                    v = [Number(minimum=self._MIN.get(wid, 0.0))]
                else:
                    v = None
                yield Input(value=str(self._get(s, sect, key, "")), id=f"f_{wid}", validators=v)
            for wid, label, sect, key, dflt in self._SWITCHES:
                with Horizontal(classes="row"):
                    yield Switch(value=bool(self._get(s, sect, key, dflt)), id=f"s_{wid}")
                    yield Label(label, classes="switch-label")
        with Horizontal(id="buttons"):
            yield Button("Attacks", id="attacks")
            yield Button("Back", id="back", variant="primary")
        yield Footer()

    @staticmethod
    def _get(s: dict, sect: str, key: str, dflt: Any) -> Any:
        node = s.get(sect, {})
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.get(part, {})
        return node.get(parts[-1], dflt)

    def _set(self, sect: str, key: str, val: Any) -> None:
        node = self.app.settings.setdefault(sect, {})
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = val

    def _save(self) -> None:
        for wid, _l, sect, key, typ in self._FIELDS:
            raw = self.query_one(f"#f_{wid}", Input).value.strip()
            if typ is int:
                try:
                    val: Any = int(float(raw))
                except ValueError:
                    val = self._get(self.app.settings, sect, key, self._MIN.get(wid, 0))
            elif typ is float:
                try:
                    val = float(raw)
                except ValueError:
                    val = self._get(self.app.settings, sect, key, self._MIN.get(wid, 0.0))
            else:
                val = raw
                if wid == "url" and val and "://" not in val:
                    val = "https://" + val
                elif wid == "model" and not val:
                    val = self._get(self.app.settings, sect, key, val)
            if wid in self._MIN and isinstance(val, (int, float)) and not isinstance(val, bool):
                val = max(self._MIN[wid], val)
            self._set(sect, key, val)
        for wid, _l, sect, key, _d in self._SWITCHES:
            self._set(sect, key, self.query_one(f"#s_{wid}", Switch).value)

    def action_back(self) -> None:
        self._save()
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self._save()
        if event.button.id == "attacks":
            self.app.push_screen(AttacksScreen())
        elif event.button.id == "back":
            self.app.pop_screen()


class AttacksScreen(Screen):
    BINDINGS = [("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        at = self.app.settings.setdefault("scanner", {}).setdefault("attacks", {})
        yield Static("GRADIENTQL   attacks", id="title")
        with VerticalScroll(id="form"):
            for name, dflt in _ATTACK_DEFAULTS:
                with Horizontal(classes="row"):
                    yield Switch(value=bool(at.get(name, dflt)), id=f"a_{name}")
                    yield Label(_ATTACK_LABELS.get(name, name), classes="switch-label")
        yield Button("Back", id="back", variant="primary")
        yield Footer()

    def _save(self) -> None:
        at = self.app.settings.setdefault("scanner", {}).setdefault("attacks", {})
        for name, _d in _ATTACK_DEFAULTS:
            at[name] = self.query_one(f"#a_{name}", Switch).value

    def action_back(self) -> None:
        self._save()
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self._save()
        self.app.pop_screen()


class DashboardScreen(Screen):
    BINDINGS = [("escape", "back", "Stop & back")]

    def __init__(self, resume: dict[str, Any] | None = None) -> None:
        super().__init__()
        self._start = 0.0
        self._shown = 0
        self._step = 0
        self._budget = 0
        self._ctx: Any = None
        self._alive = True
        self._settings: dict[str, Any] = {}
        self._steer_q: queue.Queue = queue.Queue()
        self._resume = resume
        self._run_id: str | None = resume.get("run_id") if resume else None

    def on_unmount(self) -> None:
        self._alive = False

    def _drain_steer(self) -> list[str]:
        out: list[str] = []
        try:
            while True:
                out.append(self._steer_q.get_nowait())
        except queue.Empty:
            pass
        return out

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "steer":
            return
        msg = event.value.strip()
        event.input.value = ""
        if msg:
            self._steer_q.put(msg)
            self._log(f"operator: {msg}", f"bold {GOLD_HI}")

    def compose(self) -> ComposeResult:
        yield Static("", id="dash_header", markup=False)
        with Horizontal(id="statbar"):
            yield ProgressBar(total=100, show_eta=False, id="pbar")
            yield Static("", id="stats", markup=False)
        with Horizontal(id="dash_body"):
            with VerticalScroll(id="cov_scroll"):
                yield Static(coverage_text(None), id="coverage")
            yield RichLog(id="activity", wrap=True, markup=False, highlight=False, max_lines=500)
            with VerticalScroll(id="loot_scroll"):
                yield Static(loot_text(None), id="loot")
        yield DataTable(id="findings")
        yield Input(placeholder="steer the agent — e.g. 'search for DoS now' — press Enter to send", id="steer")
        yield Footer()

    def _set_header(self, status: str, style: str, detail: str) -> None:
        if not self._alive:
            return
        t = Text()
        t.append("GRADIENTQL  ", style=f"bold {GOLD}")
        t.append(status, style=style)
        t.append("  " + detail, style="grey70")
        self.query_one("#dash_header", Static).update(t)

    def _log(self, msg: str, style: str) -> None:
        if self._alive:
            self.query_one("#activity", RichLog).write(Text(msg, style=style))

    def on_mount(self) -> None:
        if self._resume is None:  # a resumed run keeps the target action_resume set from the checkpoint
            self.app.target = self.app.settings.get("target", {}).get("url") or self.app.target
        self._settings = copy.deepcopy(self.app.settings)
        self.query_one("#cov_scroll").border_title = "coverage map"
        activity = self.query_one("#activity")
        activity.border_title = "activity"
        activity.border_subtitle = "! finding   x error   + auth   - dead"
        self.query_one("#loot_scroll").border_title = "loot"
        tbl = self.query_one("#findings", DataTable)
        tbl.border_title = "findings"
        self.query_one("#steer", Input).border_title = "steer the agent"
        tbl.add_columns("score", "finding", "target")
        self._set_header("VERIFYING", "yellow", self.app.target)
        self._start = time.monotonic()
        self.set_interval(1.0, self._tick)
        self.run_scan()

    @work(thread=True, group="scan")
    def run_scan(self) -> None:
        from .core.llm import verify_key
        from .scanner import checkpoint as _cp
        from .scanner.run import run_scan
        self.app.scan_active = True
        try:
            ok, msg = verify_key(self._settings)
            if not ok:
                self.app.call_from_thread(self._blocked, msg)
                return
            if self._run_id is None:
                self._run_id = _cp.new_run_id()
            verb = "resuming" if self._resume else "scanning"
            self.app.call_from_thread(self._set_header, "SCANNING", f"bold {GOLD_HI}", self.app.target)
            self.app.call_from_thread(self._log, f"{verb} {self.app.target}", "grey62")
            if _cp.is_enabled(self._settings):
                start_at = (int(self._resume.get("step", -1)) + 1) if self._resume else 0
                self.app.call_from_thread(
                    self._log,
                    f"run {self._run_id} · auto-checkpoint every {_cp.interval(self._settings)} steps"
                    + (f" · resuming at step {start_at}" if self._resume else ""),
                    f"bold {GOLD}")
            try:
                result = run_scan(self._settings, self.app.target, progress_cb=self._on_step,
                                  report=False, should_stop=lambda: not self._alive,
                                  steer=self._drain_steer, run_id=self._run_id, resume=self._resume)
            except Exception as e:  # noqa: BLE001
                result = {"vulnerabilities": [], "target_url": self.app.target, "steps": 0,
                          "interactions": [], "error": f"scan error: {str(e)[:120]}"}
            self.app.call_from_thread(self._done, result)
        finally:
            self.app.scan_active = False

    def _blocked(self, msg: str) -> None:
        self.app.result = None
        self._set_header("CANNOT START", f"bold {ERR_RED}", msg + "   (esc to go back)")
        self._log(msg, f"bold {ERR_RED}")

    def _on_step(self, step: int, budget: int, ctx: Any) -> None:
        self.app.call_from_thread(self._update, step, budget, ctx)

    def _stats_text(self) -> str:
        ctx = self._ctx
        el = time.monotonic() - self._start if self._start else 0.0
        mm, ss = divmod(int(el), 60)
        reqs = len(ctx.interactions) if ctx else 0
        finds = len(ctx.vulns) if ctx else 0
        rate = reqs / el if el > 0 else 0.0
        ident = memory.identity_label(ctx.identity) if ctx else "anon"
        auth = "auth" if ident not in ("anon", "hdr") else "anon"
        pct = int(self._step / self._budget * 100) if self._budget else 0
        model = self.app.settings.get("llm", {}).get("attacker_model", "?")
        tok = getattr(ctx, "tokens", None) or {}
        tt = tok.get("total", 0)
        tks = f"{tt / 1000:.1f}k" if tt >= 1000 else str(tt)
        cost = f" ~${tok['cost']:.2f}" if tok.get("cost") else ""
        return (f"step {self._step}/{self._budget} {pct}%    {mm:02d}:{ss:02d}    "
                f"req {reqs} ({rate:.1f}/s)    find {finds}    tok {tks}{cost}    {auth}    {model}")

    def _tick(self) -> None:
        if self._alive and self._ctx is not None:
            self.query_one("#stats", Static).update(self._stats_text())

    def _update(self, step: int, budget: int, ctx: Any) -> None:
        self._step, self._budget, self._ctx = step, budget, ctx
        if not self._alive:
            return
        self.query_one("#pbar", ProgressBar).update(progress=(step / budget * 100) if budget else 0)
        self.query_one("#stats", Static).update(self._stats_text())
        log = self.query_one("#activity", RichLog)
        for line in ctx.decisions[self._shown:]:
            log.write(_activity_text(str(line)))
        self._shown = len(ctx.decisions)
        self.query_one("#coverage", Static).update(coverage_text(ctx))
        self.query_one("#loot", Static).update(loot_text(ctx))
        tbl = self.query_one("#findings", DataTable)
        tbl.clear()
        for v in ctx.vulns[-10:]:
            tbl.add_row(f"{float(v.get('score', 0)):.1f}", str(v.get("vuln_type", ""))[:44],
                        str(v.get("target_node", ""))[:28])

    def _done(self, result: dict[str, Any]) -> None:
        self.app.result = result
        if not self._alive:
            return
        err = result.get("error")
        if err:
            self._set_header("FAILED", f"bold {ERR_RED}", str(err) + "   (esc to go back)")
            self._log(str(err), f"bold {ERR_RED}")
            return
        n = len(result.get("vulnerabilities", []))
        self._set_header("COMPLETE", f"bold {OK_GREEN}", f"{n} findings   (esc to go back)")
        self._log(f"scan complete, {n} finding(s)", f"bold {OK_GREEN}")
        rid = result.get("run_id") or self._run_id
        from .scanner import checkpoint as _cp
        if rid and _cp.is_enabled(self._settings):
            self._log(f"resume this run:  gradientql --resume {rid}", "grey62")

    def action_back(self) -> None:
        self.app.pop_screen()


class GradientQLApp(App):
    TITLE = "GradientQL"
    CSS = """
    Screen { align: left top; }
    #logo_row { height: auto; }
    #menu_row { height: auto; }
    #logo { width: auto; height: auto; margin: 1 0 0 0; }
    #menu { width: 66; height: auto; border: double $primary; padding: 1 2; margin-top: 1; }
    #menu Button { width: 100%; margin-bottom: 1; }
    #summary { margin-top: 1; color: $text-muted; }
    #title { text-style: bold; color: $primary; padding: 1 1 0 1; }
    #form { height: 1fr; padding: 1 2; }
    #form Label { color: $text-muted; }
    #form Input { margin-bottom: 1; }
    .row { height: 3; }
    .row Switch { margin-right: 2; }
    .switch-label { padding-top: 1; }
    #buttons { height: auto; padding: 1 2; }
    #buttons Button { margin-right: 2; }
    #dash_header { text-style: bold; color: $primary; padding: 0 1; height: 1; }
    #statbar { height: 1; padding: 0 1; margin-bottom: 1; }
    #statbar #pbar { width: 28; }
    #statbar #stats { width: 1fr; color: $accent; padding-left: 2; }
    #dash_body { height: 1fr; }
    #cov_scroll { width: 33%; border: double $primary; padding: 0 1; }
    #activity { width: 40%; border: double $primary; padding: 0 1;
                background: transparent; scrollbar-size-horizontal: 0; scrollbar-size-vertical: 1;
                scrollbar-background: $background; scrollbar-color: $primary; }
    #loot_scroll { width: 27%; border: double $primary; padding: 0 1; }
    #coverage { width: auto; height: auto; }
    #loot { width: auto; height: auto; }
    #findings { height: 9; border: double $primary; }
    #steer { height: 3; border: double $accent; }
    """

    def __init__(self, settings: dict[str, Any], target: str | None = None) -> None:
        super().__init__()
        self.settings = settings
        self.target = target or (settings.get("target", {}).get("url") or "")
        self.result: dict[str, Any] | None = None
        self.scan_active = False

    def on_mount(self) -> None:
        self.register_theme(_THEME)
        self.theme = "gradientql"
        self.push_screen(MenuScreen())


def launch(settings_path: str | None = None, target_url: str | None = None,
           trace: Any = None, verbose: bool = False) -> dict[str, Any] | None:
    import warnings

    from .core.config import load_settings
    from .utils.logger import setup_logging

    warnings.filterwarnings("ignore")
    setup_logging("CRITICAL")
    settings = load_settings(settings_path)
    if trace is not None:
        settings.setdefault("scanner", {})["trace"] = trace
    if verbose:
        settings.setdefault("scanner", {})["verbose"] = True
    if target_url:
        settings.setdefault("target", {})["url"] = target_url
    app = GradientQLApp(settings, target_url)
    app.run()
    return app.result

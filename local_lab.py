from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Any


ROOT = Path(__file__).resolve().parent
LOCAL_DATA_ROOT = Path(os.environ.get("LOCALAPPDATA", str(ROOT)))
DATA_DIR = LOCAL_DATA_ROOT / "CybersecurityOperationsLab"
EVENT_LIMIT = 1000
DISPLAY_LIMIT = 1000
WINDOWS = {
    "Past hour": 1,
    "Past 6 hours": 6,
    "Past 24 hours": 24,
    "Past 7 days": 168,
}

SOURCES: dict[str, tuple[str, str, str, str]] = {
    "security": (
        "Windows Security events",
        "windows.security",
        "Windows security log records from the selected time period.",
        "A record describes an audited event. It does not by itself establish why it occurred or whether it was harmful.",
    ),
    "system": (
        "Windows System events",
        "windows.system",
        "Windows and driver events from the selected time period.",
        "These records can help explain service, device, and operating-system activity.",
    ),
    "application": (
        "Windows Application events",
        "windows.application",
        "Application-generated Windows events from the selected time period.",
        "These records can help explain application errors and activity.",
    ),
    "powershell": (
        "PowerShell events",
        "windows.powershell",
        "PowerShell Operational log records from the selected time period.",
        "These records can show logged PowerShell activity. Logging settings determine what details are present.",
    ),
    "connections": (
        "Current TCP connections",
        "network.connections",
        "A point-in-time view of TCP connections visible when you collect.",
        "A connection is not a history of network activity and does not show intent. The associated process is identified when Windows permits it.",
    ),
    "listeners": (
        "Listening and bound ports",
        "network.listeners",
        "TCP listening ports and UDP endpoints visible when you collect.",
        "A listening or bound port is not proof that it was contacted or exposed to the internet.",
    ),
    "interfaces": (
        "Network interfaces",
        "network.interfaces",
        "Configured network interfaces and their addresses at collection time.",
        "An address shows local network configuration, not who communicated with the device.",
    ),
    "processes": (
        "Running processes",
        "processes.running",
        "Processes visible on this computer at collection time.",
        "A process name or resource measurement alone does not establish what the process did or whether it is safe.",
    ),
    "dns_cache": (
        "Local DNS cache",
        "network.dns_cache",
        "DNS entries still present in the Windows client cache at collection time.",
        "A cache entry is not a complete browsing history. Its presence or absence does not prove whether a domain was visited.",
    ),
}

EVENT_NOTES = {
    ("security", "4624"): "Windows recorded a successful account logon. Review the account, logon type, and source fields; this event alone does not show whether the access was expected.",
    ("security", "4625"): "Windows recorded a failed account logon. Repeated failures can have several causes; check the account, logon type, source, and surrounding events before drawing conclusions.",
    ("security", "4634"): "Windows recorded that an account logon session ended. This is useful timeline context, not evidence of a security problem by itself.",
    ("security", "4648"): "Windows recorded an attempt to log on using explicitly supplied credentials. This can occur in legitimate administration; inspect the account and process context.",
    ("security", "4688"): "Windows recorded process creation. The command line may be missing unless the relevant audit policy is enabled.",
    ("security", "4720"): "Windows recorded creation of a user account. Check which account performed the action and whether the new account was expected.",
    ("security", "4722"): "Windows recorded that a user account was enabled. This event alone does not establish whether the change was authorized.",
    ("security", "4725"): "Windows recorded that a user account was disabled. Compare the actor and timing with expected account administration.",
    ("security", "4726"): "Windows recorded deletion of a user account. Review who performed the change and its surrounding context.",
    ("security", "4732"): "Windows recorded a member being added to a local security group. Check the group, member, and account that made the change.",
    ("powershell", "4103"): "PowerShell module logging recorded activity. The available detail depends on the machine's logging configuration.",
    ("powershell", "4104"): "PowerShell script-block logging recorded script content processed by PowerShell. This is evidence of logged script activity, not by itself proof that the activity was harmful.",
    ("system", "7045"): "Windows recorded installation of a service. Many legitimate programs install services; review the service name, path, account, and timing.",
}

INVENTORY_PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Test-EventLog($name) {
    try {
        $log = Get-WinEvent -ListLog $name -ErrorAction Stop
        $null = Get-WinEvent -LogName $name -MaxEvents 1 -ErrorAction Stop
        return [pscustomobject]@{ Name = $name; Available = $true; Enabled = $log.IsEnabled; RecordsInLog = $log.RecordCount; Detail = 'Readable' }
    } catch {
        $message = $_.Exception.Message
        if ($message -match 'No events were found|NoMatchingEventsFound') {
            return [pscustomobject]@{ Name = $name; Available = $true; Enabled = $true; RecordsInLog = 0; Detail = 'Readable; no records found' }
        }
        return [pscustomobject]@{ Name = $name; Available = $false; Enabled = $null; RecordsInLog = $null; Detail = $message }
    }
}
$logs = @(
    (Test-EventLog 'Security'),
    (Test-EventLog 'System'),
    (Test-EventLog 'Application'),
    (Test-EventLog 'Microsoft-Windows-PowerShell/Operational')
)
$administrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$commands = @('Get-NetTCPConnection', 'Get-NetUDPEndpoint', 'Get-NetIPConfiguration', 'Get-DnsClientCache', 'Get-Process', 'pktmon')
$capabilities = foreach ($commandName in $commands) {
    [pscustomobject]@{ Name = $commandName; Available = [bool](Get-Command $commandName -ErrorAction SilentlyContinue) }
}
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$result = [pscustomobject]@{
    Logs = $logs
    Capabilities = @($capabilities)
    Administrator = $administrator
    Machine = $computer.Name
    OperatingSystem = $os.Caption
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
}
ConvertTo-Json -InputObject $result -Depth 6 -Compress
"""

COLLECT_PS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$hours = [int]$env:ARES_WINDOW_HOURS
$since = (Get-Date).AddHours(-$hours)
$limit = 1000
function Get-EventSource($key, $logName) {
    try {
        $null = Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop
    } catch {
        $message = $_.Exception.Message
        if ($message -notmatch 'No events were found|NoMatchingEventsFound') {
            return [pscustomobject]@{ Key = $key; Available = $false; Error = $message; LimitReached = $false; Rows = @() }
        }
    }
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; StartTime = $since } -MaxEvents $limit -ErrorAction Stop)
        $rows = foreach ($event in $events) {
            [pscustomobject]@{
                Timestamp = $event.TimeCreated.ToUniversalTime().ToString('o')
                Source = $logName
                EventId = $event.Id
                Provider = $event.ProviderName
                Level = $event.LevelDisplayName
                RecordId = $event.RecordId
                Machine = $event.MachineName
                Message = $event.Message
            }
        }
        return [pscustomobject]@{ Key = $key; Available = $true; Error = $null; LimitReached = ($events.Count -ge $limit); Rows = @($rows) }
    } catch {
        $message = $_.Exception.Message
        if ($message -match 'No events were found|NoMatchingEventsFound') {
            return [pscustomobject]@{ Key = $key; Available = $true; Error = $null; LimitReached = $false; Rows = @() }
        }
        return [pscustomobject]@{ Key = $key; Available = $false; Error = $message; LimitReached = $false; Rows = @() }
    }
}
function Get-Snapshot($key, $query) {
    try {
        $rows = @(& $query)
        return [pscustomobject]@{ Key = $key; Available = $true; Error = $null; LimitReached = $false; Rows = $rows }
    } catch {
        return [pscustomobject]@{ Key = $key; Available = $false; Error = $_.Exception.Message; LimitReached = $false; Rows = @() }
    }
}
$processRows = @(Get-Process -ErrorAction Stop)
$processById = @{}
foreach ($item in $processRows) {
    $processById[[string]$item.Id] = $item.ProcessName
}
$processResult = Get-Snapshot 'processes' {
    foreach ($item in $processRows) {
        $start = $null
        try { $start = $item.StartTime.ToUniversalTime().ToString('o') } catch { }
        $cpu = $null
        try { $cpu = [math]::Round($item.CPU, 2) } catch { }
        [pscustomobject]@{
            Timestamp = [DateTime]::UtcNow.ToString('o')
            Name = $item.ProcessName
            ProcessId = $item.Id
            StartTimeUtc = $start
            CpuSeconds = $cpu
            WorkingSetMB = [math]::Round($item.WorkingSet64 / 1MB, 1)
        }
    }
}
$connectionResult = Get-Snapshot 'connections' {
    foreach ($item in @(Get-NetTCPConnection -ErrorAction Stop)) {
        $processName = $processById[[string]$item.OwningProcess]
        if (-not $processName) { $processName = 'Unavailable' }
        [pscustomobject]@{
            Timestamp = [DateTime]::UtcNow.ToString('o')
            Protocol = 'TCP'
            State = [string]$item.State
            LocalAddress = $item.LocalAddress
            LocalPort = $item.LocalPort
            RemoteAddress = $item.RemoteAddress
            RemotePort = $item.RemotePort
            ProcessId = $item.OwningProcess
            ProcessName = $processName
        }
    }
}
$listenerResult = Get-Snapshot 'listeners' {
    foreach ($item in @(Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
        $processName = $processById[[string]$item.OwningProcess]
        if (-not $processName) { $processName = 'Unavailable' }
        [pscustomobject]@{
            Timestamp = [DateTime]::UtcNow.ToString('o')
            Protocol = 'TCP'
            State = 'Listening'
            LocalAddress = $item.LocalAddress
            LocalPort = $item.LocalPort
            ProcessId = $item.OwningProcess
            ProcessName = $processName
        }
    }
    foreach ($item in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
        $processName = $processById[[string]$item.OwningProcess]
        if (-not $processName) { $processName = 'Unavailable' }
        [pscustomobject]@{
            Timestamp = [DateTime]::UtcNow.ToString('o')
            Protocol = 'UDP'
            State = 'Bound; UDP has no connection state'
            LocalAddress = $item.LocalAddress
            LocalPort = $item.LocalPort
            ProcessId = $item.OwningProcess
            ProcessName = $processName
        }
    }
}
$interfaceResult = Get-Snapshot 'interfaces' {
    foreach ($item in @(Get-NetIPConfiguration -ErrorAction Stop)) {
        [pscustomobject]@{
            Timestamp = [DateTime]::UtcNow.ToString('o')
            Interface = $item.InterfaceAlias
            InterfaceDescription = $item.NetAdapter.InterfaceDescription
            IPv4Addresses = (@($item.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', ')
            IPv6Addresses = (@($item.IPv6Address | ForEach-Object { $_.IPAddress }) -join ', ')
            Gateways = (@($item.IPv4DefaultGateway, $item.IPv6DefaultGateway | Where-Object { $_ } | ForEach-Object { $_.NextHop }) -join ', ')
            DnsServers = (@($item.DnsServer.ServerAddresses) -join ', ')
            Status = [string]$item.NetAdapter.Status
        }
    }
}
$dnsResult = Get-Snapshot 'dns_cache' {
    foreach ($item in @(Get-DnsClientCache -ErrorAction Stop | Select-Object -First 1000)) {
        [pscustomobject]@{
            Timestamp = [DateTime]::UtcNow.ToString('o')
            Entry = $item.Entry
            Name = $item.Name
            Type = $item.Type
            Data = $item.Data
            Status = $item.Status
            TimeToLive = $item.TimeToLive
        }
    }
}
$sources = @(
    (Get-EventSource 'security' 'Security'),
    (Get-EventSource 'system' 'System'),
    (Get-EventSource 'application' 'Application'),
    (Get-EventSource 'powershell' 'Microsoft-Windows-PowerShell/Operational'),
    $processResult,
    $connectionResult,
    $listenerResult,
    $interfaceResult,
    $dnsResult
)
$result = [pscustomobject]@{
    CapturedAtUtc = [DateTime]::UtcNow.ToString('o')
    WindowHours = $hours
    Machine = $env:COMPUTERNAME
    Sources = @($sources)
}
ConvertTo-Json -InputObject $result -Depth 8 -Compress
"""


def run_powershell(script: str, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    encoded = __import__("base64").b64encode(script.encode("utf-16le")).decode("ascii")
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"PowerShell exited with code {result.returncode}."
        raise RuntimeError(detail)
    output = result.stdout.strip()
    if not output:
        raise RuntimeError("Windows returned no telemetry inventory.")
    return json.loads(output)


class TelemetryLab:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Local Telemetry Lab")
        self.root.geometry("1120x760")
        self.root.minsize(900, 600)
        self.root.configure(bg="#f2f5f7")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.messages: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.inventory: dict[str, Any] | None = None
        self.rows: list[dict[str, Any]] = []
        self.visible_rows: list[dict[str, Any]] = []
        self.sort_column: str | None = None
        self.sort_ascending = True
        self.collection_note = ""
        self.capture_path: Path | None = None
        self.pending_close = False
        self.current_manifest: dict[str, Any] = {}
        self.observations: list[dict[str, Any]] = []
        self.selected_observation: dict[str, Any] | None = None
        self.selected_record: dict[str, Any] | None = None
        self.investigations: list[dict[str, Any]] = []
        self.selected_investigation: dict[str, Any] | None = None
        self.nav_buttons: dict[str, tk.Button] = {}
        self.pages: dict[str, tk.Frame] = {}
        self.active_page = "Overview"
        self.source_labels = {key: value[0] for key, value in SOURCES.items()}
        self.label_sources = {value[0]: key for key, value in SOURCES.items()}

        self.configure_styles()
        self.build_ui()
        self.refresh_sessions()
        self.set_busy(True, "Checking Windows telemetry access…")
        threading.Thread(target=self.inventory_worker, daemon=True).start()
        self.root.after(120, self.process_messages)

    def configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f2f5f7")
        style.configure("Panel.TFrame", background="#ffffff")
        style.configure("TLabel", background="#f2f5f7", foreground="#17232e", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#f2f5f7", foreground="#17232e", font=("Segoe UI Semibold", 22))
        style.configure("Subtitle.TLabel", background="#f2f5f7", foreground="#536474", font=("Segoe UI", 10))
        style.configure("PanelTitle.TLabel", background="#ffffff", foreground="#17232e", font=("Segoe UI Semibold", 12))
        style.configure("PanelText.TLabel", background="#ffffff", foreground="#425464", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 7))
        style.configure("Accent.TButton", background="#1769aa", foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#125587"), ("disabled", "#91a9bb")])
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 9), background="#ffffff", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 9), background="#e8eef2", foreground="#17232e")
        style.configure("TNotebook", background="#f2f5f7", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 8), font=("Segoe UI Semibold", 10))

    def build_ui(self) -> None:
        self.root.title("Cybersecurity Operations Investigation Lab")
        self.root.geometry("1440x900")
        self.root.minsize(1080, 700)
        self.root.configure(bg="#f3f6f8")

        shell = tk.Frame(self.root, bg="#f3f6f8")
        shell.pack(fill="both", expand=True)
        shell.grid_columnconfigure(1, weight=1)
        shell.grid_rowconfigure(0, weight=1)

        sidebar = tk.Frame(shell, bg="#142637", width=226)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)
        tk.Label(sidebar, text="FIELDNOTES", bg="#142637", fg="#f3f7fa", font=("Segoe UI Semibold", 16)).pack(anchor="w", padx=22, pady=(24, 1))
        tk.Label(sidebar, text="CYBER OPERATIONS LAB", bg="#142637", fg="#8fa6b8", font=("Segoe UI", 8)).pack(anchor="w", padx=23, pady=(0, 27))

        nav_items = (
            ("Overview", "01", self.show_overview),
            ("Collections", "02", self.show_collections),
            ("Observations", "03", self.show_observations),
            ("Investigations", "04", self.show_investigations),
            ("Evidence", "05", self.show_evidence),
            ("System", "06", self.show_system),
        )
        for label, number, command in nav_items:
            button = tk.Button(
                sidebar,
                text=f"  {number}     {label}",
                command=command,
                anchor="w",
                relief="flat",
                borderwidth=0,
                bg="#142637",
                fg="#c8d4de",
                activebackground="#203d52",
                activeforeground="#ffffff",
                font=("Segoe UI", 10),
                padx=12,
                pady=11,
                cursor="hand2",
            )
            button.pack(fill="x", padx=12, pady=2)
            self.nav_buttons[label] = button

        tk.Frame(sidebar, bg="#30495a", height=1).pack(fill="x", padx=18, pady=(20, 14))
        tk.Label(sidebar, text="LOCAL  /  SINGLE ENDPOINT", bg="#142637", fg="#8fa6b8", font=("Segoe UI", 8)).pack(anchor="w", padx=23)
        self.sidebar_machine_var = tk.StringVar(value="Checking device…")
        tk.Label(sidebar, textvariable=self.sidebar_machine_var, bg="#142637", fg="#e5edf2", font=("Segoe UI", 9), wraplength=180, justify="left").pack(anchor="w", padx=23, pady=(6, 0))
        tk.Frame(sidebar, bg="#30495a", height=1).pack(fill="x", padx=18, pady=(18, 12))
        tk.Label(sidebar, text="MONITOR  ›  TRIAGE  ›  INVESTIGATE", bg="#142637", fg="#8fa6b8", font=("Segoe UI", 7)).pack(anchor="w", padx=22)

        main = tk.Frame(shell, bg="#f3f6f8")
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        topbar = tk.Frame(main, bg="#ffffff", height=61, highlightthickness=1, highlightbackground="#e1e8ed")
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_propagate(False)
        self.page_title_var = tk.StringVar(value="Overview")
        tk.Label(topbar, textvariable=self.page_title_var, bg="#ffffff", fg="#142637", font=("Segoe UI Semibold", 13)).pack(side="left", padx=(23, 18))
        tk.Label(topbar, text="Collection", bg="#ffffff", fg="#637585", font=("Segoe UI", 9)).pack(side="left")
        self.session_var = tk.StringVar()
        self.session_box = ttk.Combobox(topbar, textvariable=self.session_var, state="readonly", width=33)
        self.session_box.pack(side="left", padx=(8, 15), pady=13)
        self.session_box.bind("<<ComboboxSelected>>", lambda _event: self.load_selected_session())
        tk.Label(topbar, text="Window", bg="#ffffff", fg="#637585", font=("Segoe UI", 9)).pack(side="left")
        self.window_var = tk.StringVar(value="Past 24 hours")
        ttk.Combobox(topbar, textvariable=self.window_var, values=list(WINDOWS), state="readonly", width=13).pack(side="left", padx=(8, 12), pady=13)
        self.collect_button = ttk.Button(topbar, text="Collect telemetry", style="Accent.TButton", command=self.collect)
        self.collect_button.pack(side="left", pady=12)

        self.status_var = tk.StringVar(value="Checking Windows telemetry access…")
        tk.Label(main, textvariable=self.status_var, anchor="w", bg="#edf2f5", fg="#506477", font=("Segoe UI", 9), padx=23, pady=6).grid(row=2, column=0, sticky="ew")
        self.content_host = tk.Frame(main, bg="#f3f6f8")
        self.content_host.grid(row=1, column=0, sticky="nsew")
        self.content_host.grid_rowconfigure(0, weight=1)
        self.content_host.grid_columnconfigure(0, weight=1)

        self.pages = {name: tk.Frame(self.content_host, bg="#f3f6f8") for name in ("Overview", "Collections", "Observations", "Investigations", "Evidence", "System")}
        self.build_overview_page()
        self.build_collections_page()
        self.build_observations_page()
        self.build_investigations_page()
        self.build_evidence_page()
        self.build_system_page()
        self.set_page("Overview")

    def page_body(self, page_name: str) -> tk.Frame:
        page = self.pages[page_name]
        canvas = tk.Canvas(page, bg="#f3f6f8", highlightthickness=0)
        scrollbar = ttk.Scrollbar(page, orient="vertical", command=canvas.yview)
        body = tk.Frame(canvas, bg="#f3f6f8", padx=24, pady=22)
        body_id = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(body_id, width=event.width))
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return body

    @staticmethod
    def section_title(parent: tk.Misc, title: str, subtitle: str | None = None) -> None:
        tk.Label(parent, text=title, bg="#f3f6f8", fg="#142637", font=("Segoe UI Semibold", 18)).pack(anchor="w")
        if subtitle:
            tk.Label(parent, text=subtitle, bg="#f3f6f8", fg="#627586", font=("Segoe UI", 9), wraplength=1050, justify="left").pack(anchor="w", pady=(4, 14))

    @staticmethod
    def make_panel(parent: tk.Misc, *, padding: int = 16, bg: str = "#ffffff") -> tk.Frame:
        return tk.Frame(parent, bg=bg, padx=padding, pady=padding, highlightthickness=1, highlightbackground="#e0e7ec")

    @staticmethod
    def add_button(parent: tk.Misc, text: str, command: Any, *, primary: bool = False) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            relief="flat",
            borderwidth=0,
            bg="#1769aa" if primary else "#edf2f5",
            fg="#ffffff" if primary else "#234052",
            activebackground="#125587" if primary else "#dce6ec",
            activeforeground="#ffffff" if primary else "#142637",
            font=("Segoe UI Semibold", 9),
            padx=12,
            pady=8,
            cursor="hand2",
        )

    def set_page(self, name: str) -> None:
        for page in self.pages.values():
            page.grid_forget()
        self.pages[name].grid(row=0, column=0, sticky="nsew")
        self.active_page = name
        self.page_title_var.set(name)
        for label, button in self.nav_buttons.items():
            active = label == name
            button.configure(bg="#23445a" if active else "#142637", fg="#ffffff" if active else "#c8d4de")

    def show_overview(self) -> None:
        self.set_page("Overview")

    def show_collections(self) -> None:
        self.set_page("Collections")
        self.render_collections()

    def show_observations(self) -> None:
        self.set_page("Observations")
        self.render_observations()

    def show_investigations(self) -> None:
        self.set_page("Investigations")
        self.load_investigations()
        self.render_investigations()

    def show_evidence(self) -> None:
        self.set_page("Evidence")
        self.apply_filters()

    def show_system(self) -> None:
        self.set_page("System")
        self.render_system()

    def build_overview_page(self) -> None:
        body = self.page_body("Overview")
        intro = tk.Frame(body, bg="#142637", padx=22, pady=18)
        intro.pack(fill="x", pady=(0, 14))
        tk.Label(intro, text="CYBERSECURITY OPERATIONS LAB", bg="#142637", fg="#92c8e8", font=("Segoe UI Semibold", 9)).pack(anchor="w")
        tk.Label(intro, text="Evidence-led monitoring and investigation", bg="#142637", fg="#ffffff", font=("Segoe UI Semibold", 20)).pack(anchor="w", pady=(5, 2))
        tk.Label(intro, text="Real telemetry collected locally from this Windows endpoint. No production SOC connection or automatic security verdicts.", bg="#142637", fg="#d1dce4", font=("Segoe UI", 9), wraplength=1000, justify="left").pack(anchor="w")
        self.overview_collection_var = tk.StringVar(value="No collection selected")
        tk.Label(intro, textvariable=self.overview_collection_var, bg="#142637", fg="#b9d7e8", font=("Segoe UI", 9)).pack(anchor="w", pady=(11, 0))

        self.metric_row = tk.Frame(body, bg="#f3f6f8")
        self.metric_row.pack(fill="x", pady=(0, 17))
        for column in range(4):
            self.metric_row.grid_columnconfigure(column, weight=1, uniform="metrics")

        source_heading = tk.Frame(body, bg="#f3f6f8")
        source_heading.pack(fill="x", pady=(1, 9))
        tk.Label(source_heading, text="DATA SOURCES", bg="#f3f6f8", fg="#142637", font=("Segoe UI Semibold", 11)).pack(side="left")
        tk.Label(source_heading, text="Counts and status from the selected collection", bg="#f3f6f8", fg="#627586", font=("Segoe UI", 9)).pack(side="left", padx=(10, 0))
        self.source_cards = tk.Frame(body, bg="#f3f6f8")
        self.source_cards.pack(fill="x", pady=(0, 16))

        observation_heading = tk.Frame(body, bg="#f3f6f8")
        observation_heading.pack(fill="x", pady=(0, 8))
        tk.Label(observation_heading, text="WHAT IS HAPPENING?", bg="#f3f6f8", fg="#142637", font=("Segoe UI Semibold", 11)).pack(side="left")
        self.add_button(observation_heading, "View observations", self.show_observations).pack(side="right")
        self.overview_observations = tk.Frame(body, bg="#f3f6f8")
        self.overview_observations.pack(fill="x")
        tk.Label(body, text="Local cybersecurity operations learning and investigation lab using authorized endpoint telemetry. This environment is not a production SOC and does not represent live enterprise security operations.", bg="#f3f6f8", fg="#82919c", font=("Segoe UI", 8), wraplength=1050, justify="left").pack(anchor="w", pady=(20, 0))

    def build_collections_page(self) -> None:
        body = self.page_body("Collections")
        self.section_title(body, "Collection history", "Each entry is an on-demand collection from this endpoint. Counts describe saved source records, not alerts or incidents.")
        panel = self.make_panel(body, padding=10)
        panel.pack(fill="both", expand=True)
        columns = ("time", "window", "records", "available", "unavailable", "limits")
        self.collection_tree = ttk.Treeview(panel, columns=columns, show="headings", height=16)
        headings = (("time", "Collected (UTC)"), ("window", "Window"), ("records", "Records"), ("available", "Sources available"), ("unavailable", "Unavailable"), ("limits", "Collection notes"))
        for key, heading in headings:
            self.collection_tree.heading(key, text=heading)
        for key, width in (("time", 205), ("window", 105), ("records", 100), ("available", 140), ("unavailable", 115), ("limits", 330)):
            self.collection_tree.column(key, width=width, stretch=key == "limits")
        self.collection_tree.pack(fill="both", expand=True)
        self.collection_tree.bind("<<TreeviewSelect>>", self.select_collection_row)
        self.collection_detail_var = tk.StringVar(value="Select a saved collection to open it.")
        tk.Label(body, textvariable=self.collection_detail_var, bg="#f3f6f8", fg="#627586", font=("Segoe UI", 9), anchor="w", wraplength=1000, justify="left").pack(fill="x", pady=(10, 8))
        self.add_button(body, "Open selected collection", self.open_selected_collection, primary=True).pack(anchor="w")

    def build_observations_page(self) -> None:
        body = self.page_body("Observations")
        self.section_title(body, "Observations", "Evidence-derived prompts for review. “Needs review” means context may help; it is not a threat verdict.")
        split = tk.Frame(body, bg="#f3f6f8")
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(0, weight=3, uniform="observations")
        split.grid_columnconfigure(1, weight=2, uniform="observations")
        split.grid_rowconfigure(0, weight=1)
        left = self.make_panel(split, padding=10)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        tk.Label(left, text="FROM THE SELECTED COLLECTION", bg="#ffffff", fg="#627586", font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=5, pady=(2, 8))
        self.observation_list = tk.Frame(left, bg="#ffffff")
        self.observation_list.pack(fill="both", expand=True)
        self.authentication_note_var = tk.StringVar(value="")
        tk.Label(left, textvariable=self.authentication_note_var, bg="#fff8e9", fg="#7c622e", font=("Segoe UI", 8), wraplength=520, justify="left", padx=9, pady=7).pack(fill="x", pady=(8, 0))
        right = self.make_panel(split)
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        tk.Label(right, text="OBSERVATION DETAIL", bg="#ffffff", fg="#627586", font=("Segoe UI Semibold", 8)).pack(anchor="w")
        self.observation_detail = tk.Text(right, wrap="word", height=22, font=("Segoe UI", 9), padx=10, pady=10, bg="#ffffff", fg="#263b4b", relief="flat", state="disabled")
        self.observation_detail.pack(fill="both", expand=True, pady=(8, 10))
        actions = tk.Frame(right, bg="#ffffff")
        actions.pack(fill="x")
        self.add_button(actions, "Investigate", self.start_investigation, primary=True).pack(side="left")
        self.add_button(actions, "View evidence", self.open_observation_evidence).pack(side="left", padx=(8, 0))

    def build_investigations_page(self) -> None:
        body = self.page_body("Investigations")
        self.section_title(body, "Investigation workspace", "Start a written investigation only from an observation you choose. Keep observed facts, interpretation, unknowns, and next steps separate.")
        split = tk.Frame(body, bg="#f3f6f8")
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(0, weight=2, uniform="cases")
        split.grid_columnconfigure(1, weight=5, uniform="cases")
        split.grid_rowconfigure(0, weight=1)
        case_panel = self.make_panel(split, padding=10)
        case_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        tk.Label(case_panel, text="DOCUMENTED INVESTIGATIONS", bg="#ffffff", fg="#627586", font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=5, pady=(2, 8))
        self.investigation_list = tk.Listbox(case_panel, font=("Segoe UI", 9), activestyle="none", selectbackground="#dceaf3", selectforeground="#142637", relief="flat", bg="#ffffff", fg="#263b4b", borderwidth=0, highlightthickness=0)
        self.investigation_list.pack(fill="both", expand=True)
        self.investigation_list.bind("<<ListboxSelect>>", self.select_investigation)
        self.investigation_summary = tk.StringVar(value="No investigation has been created. Select Investigate on a real observation to begin.")
        tk.Label(case_panel, textvariable=self.investigation_summary, bg="#ffffff", fg="#627586", font=("Segoe UI", 9), wraplength=290, justify="left").pack(anchor="w", pady=(9, 0))

        work_panel = self.make_panel(split, padding=14)
        work_panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self.investigation_title_var = tk.StringVar(value="No investigation selected")
        tk.Label(work_panel, textvariable=self.investigation_title_var, bg="#ffffff", fg="#142637", font=("Segoe UI Semibold", 15)).pack(anchor="w")
        self.investigation_observation_var = tk.StringVar(value="Choose an observed item and start an investigation. No cases are generated automatically.")
        tk.Label(work_panel, textvariable=self.investigation_observation_var, bg="#ffffff", fg="#627586", font=("Segoe UI", 9), wraplength=740, justify="left").pack(anchor="w", pady=(4, 12))
        fields = tk.Frame(work_panel, bg="#ffffff")
        fields.pack(fill="both", expand=True)
        fields.grid_columnconfigure(0, weight=1, uniform="notes")
        fields.grid_columnconfigure(1, weight=1, uniform="notes")
        self.investigation_texts: dict[str, tk.Text] = {}
        field_specs = (("Observed facts", "facts"), ("Interpretation", "interpretation"), ("Unknown", "unknown"), ("Next evidence / action", "next_step"))
        for index, (label, key) in enumerate(field_specs):
            row, column = divmod(index, 2)
            cell = tk.Frame(fields, bg="#ffffff")
            cell.grid(row=row, column=column, sticky="nsew", padx=(0, 7) if column == 0 else (7, 0), pady=6)
            tk.Label(cell, text=label.upper(), bg="#ffffff", fg="#627586", font=("Segoe UI Semibold", 8)).pack(anchor="w", pady=(0, 5))
            editor = tk.Text(cell, height=6, wrap="word", font=("Segoe UI", 9), padx=8, pady=7, bg="#f7f9fa", fg="#263b4b", relief="solid", borderwidth=1, highlightthickness=0)
            editor.pack(fill="both", expand=True)
            editor.bind("<KeyRelease>", lambda _event: self.mark_investigation_dirty())
            self.investigation_texts[key] = editor
        for row in range(2):
            fields.grid_rowconfigure(row, weight=1, uniform="note_rows")
        action_row = tk.Frame(work_panel, bg="#ffffff")
        action_row.pack(fill="x", pady=(10, 0))
        self.save_investigation_button = self.add_button(action_row, "Save investigation notes", self.save_investigation, primary=True)
        self.save_investigation_button.pack(side="left")
        self.investigation_saved_var = tk.StringVar(value="")
        tk.Label(action_row, textvariable=self.investigation_saved_var, bg="#ffffff", fg="#537084", font=("Segoe UI", 9)).pack(side="left", padx=(12, 0))
        tk.Label(work_panel, text="QUESTIONS TO ANSWER  ·  What happened? When? Which source? Related activity? Supporting evidence? What can be concluded, and what remains unknown?", bg="#ffffff", fg="#738391", font=("Segoe UI", 8), wraplength=770, justify="left").pack(anchor="w", pady=(12, 0))
        tk.Label(work_panel, text="RELATED RECORDS  ·  Exact shared fields are identified where available. Time proximity alone does not establish a relationship.", bg="#ffffff", fg="#627586", font=("Segoe UI Semibold", 8), wraplength=770, justify="left").pack(anchor="w", pady=(12, 5))
        self.timeline_tree = ttk.Treeview(work_panel, columns=("time", "source", "record", "basis"), show="headings", height=6)
        for key, title in (("time", "Time (UTC)"), ("source", "Source"), ("record", "Observed record"), ("basis", "Why included")):
            self.timeline_tree.heading(key, text=title)
        self.timeline_tree.column("time", width=145, stretch=False)
        self.timeline_tree.column("source", width=155, stretch=False)
        self.timeline_tree.column("record", width=250, stretch=True)
        self.timeline_tree.column("basis", width=190, stretch=True)
        self.timeline_tree.pack(fill="x", pady=(0, 4))

    def build_evidence_page(self) -> None:
        body = self.page_body("Evidence")
        self.section_title(body, "Evidence library", "Search original collected records. Evidence remains local and read-only in this viewer.")
        filters = self.make_panel(body, padding=10)
        filters.pack(fill="x", pady=(0, 10))
        tk.Label(filters, text="Source", bg="#ffffff", fg="#637585", font=("Segoe UI", 9)).pack(side="left", padx=(3, 5))
        self.source_var = tk.StringVar(value="All sources")
        self.source_box = ttk.Combobox(filters, textvariable=self.source_var, state="readonly", width=27)
        self.source_box.pack(side="left", padx=(0, 12))
        self.search_var = tk.StringVar()
        tk.Label(filters, text="Search fields, message, IP, process, port, or event ID", bg="#ffffff", fg="#637585", font=("Segoe UI", 9)).pack(side="left", padx=(0, 7))
        self.search_box = ttk.Entry(filters, textvariable=self.search_var, width=33)
        self.search_box.pack(side="left", padx=(0, 7), ipady=4)
        self.search_box.bind("<Return>", lambda _event: self.apply_filters())
        self.add_button(filters, "Search", self.apply_filters, primary=True).pack(side="left")
        self.data_summary_var = tk.StringVar(value="Select a collection to browse its records.")
        tk.Label(body, textvariable=self.data_summary_var, bg="#f3f6f8", fg="#637585", font=("Segoe UI", 9), anchor="w").pack(fill="x", pady=(0, 7))

        split = tk.Frame(body, bg="#f3f6f8")
        split.pack(fill="both", expand=True)
        split.grid_columnconfigure(0, weight=5, uniform="evidence")
        split.grid_columnconfigure(1, weight=3, uniform="evidence")
        split.grid_rowconfigure(0, weight=1)
        table_panel = self.make_panel(split, padding=6)
        table_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        columns = ("timestamp", "source", "type", "summary")
        self.data_tree = ttk.Treeview(table_panel, columns=columns, show="headings", selectmode="browse")
        for key, title in (("timestamp", "Time (UTC)"), ("source", "Source"), ("type", "Event / type"), ("summary", "Observed data")):
            self.data_tree.heading(key, text=title, command=lambda column=key: self.sort_by(column))
        for key, width in (("timestamp", 175), ("source", 178), ("type", 115), ("summary", 365)):
            self.data_tree.column(key, width=width, stretch=key == "summary")
        yscroll = ttk.Scrollbar(table_panel, orient="vertical", command=self.data_tree.yview)
        self.data_tree.configure(yscrollcommand=yscroll.set)
        self.data_tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        self.data_tree.bind("<<TreeviewSelect>>", self.show_selected_record)

        detail_panel = self.make_panel(split, padding=12)
        detail_panel.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        tk.Label(detail_panel, text="EVIDENCE SUMMARY", bg="#ffffff", fg="#627586", font=("Segoe UI Semibold", 8)).pack(anchor="w")
        self.detail_text = tk.Text(detail_panel, wrap="word", font=("Segoe UI", 9), padx=9, pady=9, bg="#ffffff", fg="#263b4b", relief="flat", state="disabled")
        self.detail_text.pack(fill="both", expand=True, pady=(7, 8))
        self.add_button(detail_panel, "Show complete technical fields", self.toggle_raw_evidence).pack(anchor="w")
        self.raw_visible = False
        self.raw_frame = tk.Frame(detail_panel, bg="#ffffff")
        self.raw_text = tk.Text(self.raw_frame, height=10, wrap="none", font=("Consolas", 8), padx=8, pady=7, bg="#f7f9fa", fg="#263b4b", relief="solid", borderwidth=1, state="disabled")
        self.raw_text.pack(fill="both", expand=True)

    def build_system_page(self) -> None:
        body = self.page_body("System")
        self.section_title(body, "System and access", "The availability check uses this Windows session. A source can be present on the device but inaccessible to the current account.")
        device = self.make_panel(body)
        device.pack(fill="x", pady=(0, 12))
        self.system_device_var = tk.StringVar(value="Checking Windows environment…")
        tk.Label(device, textvariable=self.system_device_var, bg="#ffffff", fg="#142637", font=("Segoe UI Semibold", 11)).pack(anchor="w")
        self.system_access_tree = ttk.Treeview(body, columns=("source", "status", "explanation"), show="headings", height=11)
        for key, title in (("source", "Source"), ("status", "Access"), ("explanation", "Meaning and limitations")):
            self.system_access_tree.heading(key, text=title)
        self.system_access_tree.column("source", width=240, stretch=False)
        self.system_access_tree.column("status", width=150, stretch=False)
        self.system_access_tree.column("explanation", width=700, stretch=True)
        self.system_access_tree.pack(fill="x", pady=(0, 12))
        capture = self.make_panel(body)
        capture.pack(fill="x", pady=(0, 12))
        tk.Label(capture, text="OPTIONAL PACKET CAPTURE", bg="#ffffff", fg="#142637", font=("Segoe UI Semibold", 10)).pack(anchor="w")
        self.capture_var = tk.StringVar(value="Checking pktmon…")
        tk.Label(capture, textvariable=self.capture_var, bg="#ffffff", fg="#627586", font=("Segoe UI", 9), wraplength=1000, justify="left").pack(anchor="w", pady=(5, 9))
        capture_actions = tk.Frame(capture, bg="#ffffff")
        capture_actions.pack(anchor="w")
        self.start_capture_button = self.add_button(capture_actions, "Start capture", self.start_capture)
        self.start_capture_button.pack(side="left")
        self.stop_capture_button = self.add_button(capture_actions, "Stop and save", self.stop_capture)
        self.stop_capture_button.pack(side="left", padx=(7, 0))
        self.stop_capture_button.configure(state="disabled")
        about = self.make_panel(body, padding=14)
        about.pack(fill="x")
        tk.Label(about, text="ABOUT THIS LAB", bg="#ffffff", fg="#142637", font=("Segoe UI Semibold", 9)).pack(anchor="w")
        tk.Label(about, text="Local cybersecurity operations learning and investigation lab using authorized endpoint telemetry. This environment is not a production SOC and does not represent live enterprise security operations.", bg="#ffffff", fg="#627586", font=("Segoe UI", 9), wraplength=1000, justify="left").pack(anchor="w", pady=(5, 0))

    def set_busy(self, busy: bool, message: str) -> None:
        self.status_var.set(message)
        self.collect_button.configure(state="disabled" if busy else "normal")

    def inventory_worker(self) -> None:
        try:
            self.messages.put(("inventory", run_powershell(INVENTORY_PS)))
        except Exception as error:
            self.messages.put(("error", str(error)))

    def process_messages(self) -> None:
        try:
            while True:
                kind, payload = self.messages.get_nowait()
                if kind == "inventory":
                    self.inventory = payload
                    self.render_inventory()
                    self.refresh_sessions()
                    if self.session_var.get():
                        self.load_selected_session()
                        self.set_busy(False, "Loaded saved local evidence. No data was collected during startup.")
                    else:
                        self.set_busy(False, "Ready. No saved collection exists yet; collect only when you choose.")
                        self.render_overview()
                        self.render_observations()
                elif kind == "collection":
                    self.save_collection(payload)
                elif kind == "capture_started":
                    self.capture_path = payload
                    self.start_capture_button.configure(state="disabled")
                    self.stop_capture_button.configure(state="normal")
                    self.capture_var.set(f"Capturing to {payload}. Stop the capture when you are done.")
                elif kind == "capture_stopped":
                    self.capture_path = None
                    self.start_capture_button.configure(state="normal")
                    self.stop_capture_button.configure(state="disabled")
                    self.capture_var.set(payload)
                    if self.pending_close:
                        self.root.destroy()
                elif kind == "error":
                    if self.capture_path:
                        self.stop_capture_button.configure(state="normal")
                    elif self.inventory and self.inventory.get("Administrator"):
                        self.start_capture_button.configure(state="normal")
                    self.set_busy(False, "Action could not be completed.")
                    messagebox.showerror("Telemetry Lab", str(payload), parent=self.root)
                    if self.pending_close:
                        self.pending_close = False
        except queue.Empty:
            pass
        self.root.after(120, self.process_messages)

    def render_inventory(self) -> None:
        if not self.inventory:
            return
        machine = self.inventory.get("Machine") or "This computer"
        self.sidebar_machine_var.set(machine)
        self.system_device_var.set(
            f"{machine}  ·  {self.inventory.get('OperatingSystem') or 'Windows'}  ·  "
            f"PowerShell {self.inventory.get('PowerShellVersion') or 'unknown'}  ·  "
            f"{ 'Administrator' if self.inventory.get('Administrator') else 'Standard user' } session"
        )
        capability_map = {item.get("Name"): item.get("Available") for item in self.inventory.get("Capabilities", [])}
        log_by_name = {item.get("Name"): item for item in self.inventory.get("Logs", [])}
        log_keys = {
            "security": "Security",
            "system": "System",
            "application": "Application",
            "powershell": "Microsoft-Windows-PowerShell/Operational",
        }
        if hasattr(self, "system_access_tree"):
            for item_id in self.system_access_tree.get_children():
                self.system_access_tree.delete(item_id)
            for key, (label, _source, explanation, _meaning) in SOURCES.items():
                if key in log_keys:
                    item = log_by_name.get(log_keys[key], {})
                    available = bool(item.get("Available"))
                    status = "Available" if available else "Unavailable / access restricted"
                    detail = explanation
                    if available:
                        detail += f" Enabled: {item.get('Enabled')}; records in full log: {item.get('RecordsInLog')}."
                    else:
                        detail += f" {item.get('Detail') or 'Not readable by this account.'}"
                else:
                    command_name = {
                        "connections": "Get-NetTCPConnection",
                        "listeners": "Get-NetTCPConnection",
                        "interfaces": "Get-NetIPConfiguration",
                        "dns_cache": "Get-DnsClientCache",
                        "processes": "Get-Process",
                    }.get(key)
                    if key == "listeners":
                        available = bool(capability_map.get(command_name) and capability_map.get("Get-NetUDPEndpoint"))
                    else:
                        available = bool(capability_map.get(command_name))
                    status = "Available" if available else "Unavailable"
                    detail = explanation
                self.system_access_tree.insert("", "end", values=(label, status, detail))
        if not capability_map.get("pktmon"):
            self.capture_var.set("Windows pktmon was not found. Packet capture is unavailable; event and host collection can still be used.")
            self.start_capture_button.configure(state="disabled")
        elif not self.inventory.get("Administrator"):
            self.capture_var.set("Windows pktmon is present, but capture needs Administrator access. Start the app from an elevated PowerShell window to use it.")
            self.start_capture_button.configure(state="disabled")
        else:
            self.capture_var.set("Windows pktmon is available. Capture is opt-in and records traffic on network adapters until you stop it.")

        self.render_system()

    def collect(self) -> None:
        if not self.inventory:
            messagebox.showinfo("Telemetry Lab", "Wait for the Windows availability check to finish.", parent=self.root)
            return
        label = self.window_var.get()
        hours = WINDOWS.get(label)
        if not hours:
            return
        if not messagebox.askyesno(
            "Collect local telemetry?",
            f"Collect up to {EVENT_LIMIT:,} recent records from each readable Windows event log, plus current process, network, interface, and DNS-cache snapshots?\n\n"
            "Some records can contain usernames, device details, addresses, or domain names. Files stay in your local Windows profile under AppData\\Local. Original Windows logs will not be changed.",
            parent=self.root,
        ):
            return
        self.set_busy(True, "Collecting genuine Windows telemetry…")
        threading.Thread(target=self.collection_worker, args=(hours,), daemon=True).start()

    def collection_worker(self, hours: int) -> None:
        try:
            payload = run_powershell(COLLECT_PS, {"ARES_WINDOW_HOURS": str(hours)})
            self.messages.put(("collection", payload))
        except Exception as error:
            self.messages.put(("error", str(error)))

    def save_collection(self, payload: dict[str, Any]) -> None:
        captured = payload.get("CapturedAtUtc") or datetime.now(timezone.utc).isoformat()
        try:
            collection_time = datetime.fromisoformat(captured.replace("Z", "+00:00"))
        except ValueError:
            collection_time = datetime.now(timezone.utc)
        collection_id = collection_time.strftime("%Y%m%dT%H%M%SZ")
        directory = DATA_DIR / "collections" / collection_id
        directory.mkdir(parents=True, exist_ok=True)
        manifest_sources = []
        totals = 0
        for item in payload.get("Sources", []):
            key = item.get("Key", "unknown")
            rows = item.get("Rows") or []
            available = bool(item.get("Available"))
            label, normalized_source, explanation, _meaning = SOURCES.get(
                key, (key, key, "Collected local telemetry.", "")
            )
            source_manifest = {
                "key": key,
                "name": label,
                "source": normalized_source,
                "available": available,
                "count": len(rows) if available else None,
                "detail": item.get("Error"),
                "limit_reached": bool(item.get("LimitReached")),
                "sha256": None,
            }
            manifest_sources.append(source_manifest)
            if not available:
                continue
            evidence_path = directory / f"{key}.jsonl"
            with evidence_path.open("w", encoding="utf-8", newline="\n") as evidence_file:
                for row in rows:
                    evidence_file.write(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str))
                    evidence_file.write("\n")
            digest = hashlib.sha256()
            with evidence_path.open("rb") as evidence_file:
                for block in iter(lambda: evidence_file.read(1024 * 1024), b""):
                    digest.update(block)
            source_manifest["sha256"] = digest.hexdigest()
            totals += len(rows)

        manifest = {
            "collection_id": collection_id,
            "captured_at_utc": captured,
            "machine": payload.get("Machine"),
            "window_hours": payload.get("WindowHours"),
            "total_records": totals,
            "sources": manifest_sources,
            "evidence_format": "JSON Lines; each row is a record returned by Windows at collection time.",
        }
        (directory / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        self.refresh_sessions(select_id=collection_id)
        self.load_selected_session()
        self.set_busy(False, f"Collection saved. Actual records collected: {totals:,}.")
        self.show_overview()

    def refresh_sessions(self, select_id: str | None = None) -> None:
        collections_dir = DATA_DIR / "collections"
        sessions: list[tuple[str, str]] = []
        if collections_dir.exists():
            for manifest_path in sorted(collections_dir.glob("*/manifest.json"), reverse=True):
                try:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    session_id = manifest.get("collection_id", manifest_path.parent.name)
                    stamp = manifest.get("captured_at_utc", session_id)
                    total = manifest.get("total_records", 0)
                    sessions.append((session_id, f"{stamp} | {total} records"))
                except (OSError, json.JSONDecodeError):
                    continue
        self.session_ids = [session_id for session_id, _label in sessions]
        self.session_box.configure(values=[label for _session_id, label in sessions])
        self.session_label_ids = {label: session_id for session_id, label in sessions}
        selected = next((label for session_id, label in sessions if session_id == select_id), sessions[0][1] if sessions else "")
        self.session_var.set(selected)
        if hasattr(self, "collection_tree"):
            self.render_collections()

    def load_selected_session(self) -> None:
        label = self.session_var.get()
        collection_id = getattr(self, "session_label_ids", {}).get(label)
        if not collection_id:
            return
        directory = DATA_DIR / "collections" / collection_id
        try:
            manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
            loaded: list[dict[str, Any]] = []
            for source in manifest.get("sources", []):
                if not source.get("available"):
                    continue
                path = directory / f"{source['key']}.jsonl"
                if not path.exists():
                    continue
                with path.open("r", encoding="utf-8") as source_file:
                    for line in source_file:
                        if line.strip():
                            row = json.loads(line)
                            row["_source_key"] = source["key"]
                            loaded.append(row)
        except (OSError, json.JSONDecodeError, KeyError) as error:
            messagebox.showerror("Could not open collection", str(error), parent=self.root)
            return
        self.current_manifest = manifest
        self.current_collection_id = collection_id
        self.rows = loaded
        notices = [
            f"Unavailable: {source['name']}" for source in manifest.get("sources", []) if not source.get("available")
        ]
        notices.extend(
            f"Limit reached: {source['name']}" for source in manifest.get("sources", []) if source.get("limit_reached")
        )
        self.collection_note = f"Captured {manifest.get('captured_at_utc')} | selected window: {manifest.get('window_hours')} hours"
        if notices:
            self.collection_note += " | " + "; ".join(notices)
        labels = ["All sources"] + [self.source_labels[source["key"]] for source in manifest.get("sources", []) if source.get("available") and source.get("key") in self.source_labels]
        self.source_box.configure(values=labels)
        self.source_var.set("All sources")
        self.search_var.set("")
        self.selected_record = None
        self.selected_observation = None
        self.apply_filters()
        self.build_observation_model()
        self.render_observations()
        self.render_overview()
        self.render_collections()
        self.render_patterns()

    @staticmethod
    def row_timestamp(row: dict[str, Any]) -> str:
        return str(row.get("Timestamp") or row.get("TimeCreated") or "")

    @staticmethod
    def row_summary(row: dict[str, Any]) -> str:
        preferred = (
            "Message", "EventId", "Name", "RemoteAddress", "RemotePort", "LocalAddress", "LocalPort",
            "ProcessName", "ProcessId", "Interface", "Data", "Provider", "State", "Protocol",
        )
        parts = []
        for key in preferred:
            value = row.get(key)
            if value not in (None, ""):
                text = " ".join(str(value).split())
                if key == "Message":
                    text = text[:180]
                parts.append(f"{key}={text}")
            if len(parts) == 4:
                break
        return " | ".join(parts) or "Collected record"

    def apply_filters(self) -> None:
        source_label = self.source_var.get()
        source_key = self.label_sources.get(source_label)
        needle = self.search_var.get().strip().casefold()
        self.visible_rows = [
            row for row in self.rows
            if (source_key is None or row.get("_source_key") == source_key)
            and (not needle or needle in json.dumps(row, ensure_ascii=False, default=str).casefold())
        ]
        if self.sort_column == "timestamp":
            self.visible_rows.sort(key=self.row_timestamp, reverse=not self.sort_ascending)
        elif self.sort_column == "source":
            self.visible_rows.sort(key=lambda row: self.source_labels.get(row.get("_source_key", ""), "").casefold(), reverse=not self.sort_ascending)
        elif self.sort_column == "type":
            self.visible_rows.sort(key=lambda row: row.get("_source_key", "").casefold(), reverse=not self.sort_ascending)
        elif self.sort_column == "summary":
            self.visible_rows.sort(key=lambda row: self.row_summary(row).casefold(), reverse=not self.sort_ascending)
        for item in self.data_tree.get_children():
            self.data_tree.delete(item)
        shown = self.visible_rows[:DISPLAY_LIMIT]
        for index, row in enumerate(shown):
            key = row.get("_source_key", "")
            source_name = self.source_labels.get(key, key)
            record_type = "Windows event" if key in {"security", "system", "application", "powershell"} else key.replace("_", " ").title()
            self.data_tree.insert("", "end", iid=str(index), values=(self.row_timestamp(row), source_name, record_type, self.row_summary(row)))
        suffix = f" | showing first {DISPLAY_LIMIT:,}; refine search to narrow" if len(self.visible_rows) > DISPLAY_LIMIT else ""
        self.data_summary_var.set(f"{len(self.visible_rows):,} matching records of {len(self.rows):,} collected{suffix} | {self.collection_note}")
        self.set_record_detail(None)

    def sort_by(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_ascending = not self.sort_ascending
        else:
            self.sort_column = column
            self.sort_ascending = True
        self.apply_filters()

    def show_selected_record(self, _event: tk.Event[Any]) -> None:
        selection = self.data_tree.selection()
        if not selection:
            return
        try:
            row = self.visible_rows[int(selection[0])]
        except (IndexError, ValueError):
            return
        self.set_record_detail(row)

    def set_record_detail(self, row: dict[str, Any] | None) -> None:
        self.selected_record = row
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        if row is None:
            self.detail_text.insert("1.0", "Select a record to inspect its timestamp, source, observed fields, and limitations.")
            raw = "Original collected fields are not modified."
        else:
            key = row.get("_source_key", "")
            label, _normalized, explanation, meaning = SOURCES.get(key, (key, key, "A record collected from this endpoint.", "Technical context is required to determine significance."))
            event_id = row.get("EventId")
            provider = row.get("Provider")
            message = row.get("Message")
            sections = [
                f"EVENT SUMMARY\nTime (UTC)\n{self.row_timestamp(row) or 'Not supplied'}\n\nSource\n{label}",
            ]

            if provider:
                sections.append(f"Provider\n{provider}")
            if event_id is not None:
                sections.append(f"Event ID\n{event_id}")
            if row.get("Level"):
                sections.append(f"Level\n{row['Level']}")
            if message:
                sections.append(f"Observed message\n{' '.join(str(message).split())}")
            network_fields = ("LocalAddress", "LocalPort", "RemoteAddress", "RemotePort", "Protocol", "State", "ProcessName", "ProcessId")
            actual_network = [f"{name}\n{row[name]}" for name in network_fields if row.get(name) not in (None, "")]
            if actual_network:
                sections.append("NETWORK CONNECTION\n" + "\n\n".join(actual_network))
                sections.append("WHAT THIS DOES NOT TELL US\nA network connection was observed. The remote address alone does not establish malicious activity or identify the person using it.")
            process_fields = ("Name", "ProcessId", "StartTimeUtc", "WorkingSetMB", "CpuSeconds")
            actual_process = [f"{name}\n{row[name]}" for name in process_fields if row.get(name) not in (None, "")]
            if key == "processes" and actual_process:
                sections.append("PROCESS SNAPSHOT\n" + "\n\n".join(actual_process))
                sections.append("WHY THIS MAY MATTER\nA process can provide context for endpoint events and network activity. A process name alone does not establish intent.")
            if key == "powershell":
                sections.append("POWERSHELL CONTEXT\nPowerShell is commonly used for administration and automation. Its presence alone is not evidence of malicious activity.")
            event_note = EVENT_NOTES.get((key, str(event_id)))
            if event_note:
                sections.append(f"EVENT ID IN PLAIN LANGUAGE\n{event_note}")
            sections.extend([
                f"WHAT DOES IT MEAN?\n{meaning}",
                f"WHY COULD IT MATTER?\n{explanation}",
                "WHAT DO WE NOT KNOW?\nThis record alone does not establish intent, compromise, or causation. Compare relevant records and context before drawing a conclusion.",
            ])
            self.detail_text.insert("1.0", "\n\n".join(sections))
            raw = json.dumps({name: value for name, value in row.items() if not name.startswith("_")}, indent=2, ensure_ascii=False, default=str)
        self.detail_text.configure(state="disabled")
        if hasattr(self, "raw_text"):
            self.raw_text.configure(state="normal")
            self.raw_text.delete("1.0", "end")
            self.raw_text.insert("1.0", raw)
            self.raw_text.configure(state="disabled")

    def toggle_raw_evidence(self) -> None:
        self.raw_visible = not self.raw_visible
        if self.raw_visible:
            self.raw_frame.pack(fill="both", expand=True, pady=(8, 0))
        else:
            self.raw_frame.pack_forget()

    def build_observation_model(self) -> None:
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in self.rows:
            key = row.get("_source_key", "")
            if key in {"security", "system", "application", "powershell"} and row.get("EventId") is not None:
                groups.setdefault((key, str(row["EventId"])), []).append(row)
        observations: list[dict[str, Any]] = []
        categories = {"security": "Security", "system": "System", "application": "Application", "powershell": "PowerShell"}
        for (key, event_id), matching in groups.items():
            if len(matching) < 2:
                continue
            label = self.source_labels.get(key, key)
            event_note = EVENT_NOTES.get((key, event_id), "Technical context is required to determine the significance of this event ID.")
            category = "Authentication" if key == "security" and event_id in {"4624", "4625", "4634", "4648", "4720", "4722", "4725", "4726", "4732"} else categories.get(key, "Endpoint")
            observations.append({
                "key": f"event:{key}:{event_id}",
                "category": category,
                "status": "Observed",
                "title": f"Repeated Windows event · ID {event_id}",
                "observed": f"Event ID {event_id} appears {len(matching):,} times in {label} within this collection.",
                "meaning": event_note,
                "why": "Repeated entries can be routine. Frequency alone does not show suspicious activity; review the actual records and surrounding context.",
                "source": label,
                "count": len(matching),
                "rows": matching,
            })

        remote_groups: dict[str, list[dict[str, Any]]] = {}
        for row in self.rows:
            if row.get("_source_key") != "connections":
                continue
            address = str(row.get("RemoteAddress") or "")
            if address and address not in {"0.0.0.0", "::", "127.0.0.1", "::1"}:
                remote_groups.setdefault(address, []).append(row)
        for address, matching in remote_groups.items():
            if len(matching) < 2:
                continue
            observations.append({
                "key": f"remote:{address}",
                "category": "Network",
                "status": "Observed",
                "title": "Shared remote address in connection snapshot",
                "observed": f"{len(matching):,} TCP connection records in this single snapshot have remote address {address}.",
                "meaning": "Several observed connections share this remote address in the captured snapshot.",
                "why": "This is point-in-time data, not repeated activity over time. The address alone does not establish maliciousness or identify a service.",
                "source": self.source_labels["connections"],
                "count": len(matching),
                "rows": matching,
            })
        observations.sort(key=lambda item: (-item["count"], item["category"], item["title"]))
        self.observations = observations

    def render_overview(self) -> None:
        if not hasattr(self, "metric_row"):
            return
        for child in self.metric_row.winfo_children():
            child.destroy()
        manifest = self.current_manifest
        sources = manifest.get("sources", [])
        available = sum(1 for item in sources if item.get("available"))
        unavailable = sum(1 for item in sources if not item.get("available"))
        evidence_files = sum(1 for item in sources if item.get("available") and (DATA_DIR / "collections" / getattr(self, "current_collection_id", "") / f"{item.get('key')}.jsonl").exists())
        captured = manifest.get("captured_at_utc")
        values = (
            (f"{manifest.get('total_records', 0):,}" if manifest else "—", "RECORDS COLLECTED", "#1769aa"),
            (f"{manifest.get('window_hours')}h" if manifest.get("window_hours") else "—", "COLLECTION WINDOW", "#267b78"),
            (str(available) if manifest else "—", "SOURCES AVAILABLE", "#287d58"),
            (str(unavailable) if manifest else "—", "SOURCES UNAVAILABLE", "#b07826"),
        )
        for column, (value, label, accent) in enumerate(values):
            tile = self.make_panel(self.metric_row, padding=13)
            tile.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 6, 6 if column < 3 else 0))
            tk.Label(tile, text=value, bg="#ffffff", fg=accent, font=("Segoe UI Semibold", 20)).pack(anchor="w")
            tk.Label(tile, text=label, bg="#ffffff", fg="#627586", font=("Segoe UI Semibold", 8)).pack(anchor="w", pady=(2, 0))
        self.overview_collection_var.set(
            f"{manifest.get('machine') or 'Windows endpoint'}  ·  {captured or 'No saved collection'}  ·  "
            f"{evidence_files} evidence files  ·  {'Collection loaded' if manifest else 'No collection selected'}"
        )
        for child in self.source_cards.winfo_children():
            child.destroy()
        if not manifest:
            tk.Label(self.source_cards, text="No saved collection is available yet. Choose Collect telemetry when you are ready to capture real local data.", bg="#ffffff", fg="#627586", font=("Segoe UI", 10), padx=15, pady=18).pack(fill="x")
        else:
            for column in range(3):
                self.source_cards.grid_columnconfigure(column, weight=1, uniform="source_cards")
            for index, source in enumerate(sources):
                key = source.get("key", "")
                label = self.source_labels.get(key, source.get("name", key))
                available_source = bool(source.get("available"))
                count = source.get("count")
                snapshot = key in {"connections", "listeners", "interfaces", "processes", "dns_cache"}
                status = "AVAILABLE" if available_source else "UNAVAILABLE"
                note = SOURCES.get(key, (label, "", "", ""))[2]
                if not available_source:
                    note = source.get("detail") or "Not accessible in this collection."
                elif source.get("limit_reached"):
                    note += " Collection limit reached; older matching records may not be included."
                card = self.make_panel(self.source_cards, padding=12)
                card.grid(row=index // 3, column=index % 3, sticky="nsew", padx=(0 if index % 3 == 0 else 5, 5 if index % 3 < 2 else 0), pady=(0, 8))
                top = tk.Frame(card, bg="#ffffff")
                top.pack(fill="x")
                tk.Label(top, text=label.upper(), bg="#ffffff", fg="#30495a", font=("Segoe UI Semibold", 8)).pack(side="left", anchor="w")
                tk.Label(top, text=f"● {status}" if available_source else f"○ {status}", bg="#ffffff", fg="#287d58" if available_source else "#a56a2a", font=("Segoe UI Semibold", 8)).pack(side="right")
                count_text = f"{count:,} records" if available_source and count is not None else "Access restricted" if not available_source else "Count unavailable"
                tk.Label(card, text=count_text, bg="#ffffff", fg="#142637", font=("Segoe UI Semibold", 14)).pack(anchor="w", pady=(8, 2))
                tk.Label(card, text="Point-in-time snapshot" if snapshot else "Historical event log", bg="#ffffff", fg="#1769aa", font=("Segoe UI", 8)).pack(anchor="w")
                tk.Label(card, text=note, bg="#ffffff", fg="#627586", font=("Segoe UI", 8), wraplength=310, justify="left", height=3, anchor="nw").pack(fill="x", pady=(6, 2))
                action = "Explore" if available_source else "Why unavailable"
                self.add_button(card, action, lambda source_key=key: self.explore_source(source_key)).pack(anchor="w", pady=(3, 0))
        for child in self.overview_observations.winfo_children():
            child.destroy()
        for observation in self.observations[:3]:
            self.make_observation_card(self.overview_observations, observation, compact=True).pack(fill="x", pady=(0, 7))
        if not self.observations:
            empty = self.make_panel(self.overview_observations, padding=13)
            empty.pack(fill="x")
            tk.Label(empty, text="No observations from the current simple checks", bg="#ffffff", fg="#30495a", font=("Segoe UI Semibold", 10)).pack(anchor="w")
            tk.Label(empty, text="This means the configured repeat-pattern checks produced no observation. It is not proof that nothing happened.", bg="#ffffff", fg="#627586", font=("Segoe UI", 9), wraplength=1000, justify="left").pack(anchor="w", pady=(4, 0))

    def render_collections(self) -> None:
        if not hasattr(self, "collection_tree"):
            return
        for item_id in self.collection_tree.get_children():
            self.collection_tree.delete(item_id)
        directory = DATA_DIR / "collections"
        manifests = sorted(directory.glob("*/manifest.json"), reverse=True) if directory.exists() else []
        labels: list[str] = []
        label_ids: dict[str, str] = {}
        for path in manifests:
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            collection_id = manifest.get("collection_id", path.parent.name)
            captured = manifest.get("captured_at_utc", "Unknown time")
            total = manifest.get("total_records", 0)
            available = sum(1 for source in manifest.get("sources", []) if source.get("available"))
            unavailable = sum(1 for source in manifest.get("sources", []) if not source.get("available"))
            limited = sum(1 for source in manifest.get("sources", []) if source.get("limit_reached"))
            notes = f"{unavailable} unavailable; {limited} capped" if unavailable or limited else "No source limits recorded"
            self.collection_tree.insert("", "end", iid=collection_id, values=(captured, f"{manifest.get('window_hours', '?')} hours", f"{total:,}", f"{available} / {len(manifest.get('sources', []))}", unavailable, notes))
            label = f"{captured} | {total:,} records"
            labels.append(label)
            label_ids[label] = collection_id
        self.session_box.configure(values=labels)
        self.session_label_ids = label_ids
        if self.session_var.get() not in label_ids:
            self.session_var.set(labels[0] if labels else "")
        if manifests and not self.collection_tree.selection():
            current = getattr(self, "current_collection_id", "")
            if current in self.collection_tree.get_children():
                self.collection_tree.selection_set(current)
        if not manifests:
            self.collection_detail_var.set("No collections have been saved. Nothing is created until you collect real telemetry.")

    def select_collection_row(self, _event: tk.Event[Any]) -> None:
        selection = self.collection_tree.selection()
        if not selection:
            return
        path = DATA_DIR / "collections" / selection[0] / "manifest.json"
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        unavailable = [source.get("name", source.get("key")) for source in manifest.get("sources", []) if not source.get("available")]
        capped = [source.get("name", source.get("key")) for source in manifest.get("sources", []) if source.get("limit_reached")]
        details = [f"Actual collection: {manifest.get('total_records', 0):,} records across {len(manifest.get('sources', []))} sources."]
        if unavailable:
            details.append("Unavailable: " + ", ".join(unavailable) + ".")
        if capped:
            details.append("Configured limit reached: " + ", ".join(capped) + ".")
        self.collection_detail_var.set(" ".join(details))

    def open_selected_collection(self) -> None:
        selection = self.collection_tree.selection()
        if not selection:
            return
        collection_id = selection[0]
        for label, current_id in self.session_label_ids.items():
            if current_id == collection_id:
                self.session_var.set(label)
                self.load_selected_session()
                self.show_overview()
                return

    def explore_source(self, key: str) -> None:
        label = self.source_labels.get(key)
        if not label:
            return
        if label not in tuple(self.source_box.cget("values")):
            self.show_system()
            return
        self.source_var.set(label)
        self.search_var.set("")
        self.show_evidence()

    def make_observation_card(self, parent: tk.Misc, observation: dict[str, Any], *, compact: bool = False) -> tk.Frame:
        card = self.make_panel(parent, padding=11 if compact else 13)
        title_row = tk.Frame(card, bg="#ffffff")
        title_row.pack(fill="x")
        tk.Label(title_row, text=observation["category"].upper(), bg="#ffffff", fg="#1769aa", font=("Segoe UI Semibold", 8)).pack(side="left")
        tk.Label(title_row, text=observation["status"], bg="#e8f1f5", fg="#426175", font=("Segoe UI Semibold", 8), padx=7, pady=2).pack(side="right")
        tk.Label(card, text=observation["title"], bg="#ffffff", fg="#142637", font=("Segoe UI Semibold", 11)).pack(anchor="w", pady=(6, 3))
        tk.Label(card, text=observation["observed"], bg="#ffffff", fg="#30495a", font=("Segoe UI", 9), wraplength=720, justify="left").pack(anchor="w")
        if not compact:
            tk.Label(card, text="Repeated activity is not a verdict. Inspect actual records and context.", bg="#ffffff", fg="#738391", font=("Segoe UI", 8), wraplength=720, justify="left").pack(anchor="w", pady=(5, 2))
            actions = tk.Frame(card, bg="#ffffff")
            actions.pack(fill="x", pady=(7, 0))
            self.add_button(actions, "Investigate", lambda item=observation: self.start_investigation(item), primary=True).pack(side="left")
            self.add_button(actions, "View evidence", lambda item=observation: self.view_observation_evidence(item)).pack(side="left", padx=(7, 0))
        card.bind("<Button-1>", lambda _event, item=observation: self.choose_observation(item))
        for child in card.winfo_children():
            child.bind("<Button-1>", lambda _event, item=observation: self.choose_observation(item))
        return card

    def render_observations(self) -> None:
        if not hasattr(self, "observation_list"):
            return
        security_source = next((source for source in self.current_manifest.get("sources", []) if source.get("key") == "security"), None)
        if security_source and not security_source.get("available"):
            self.authentication_note_var.set("Authentication analysis is limited because Windows Security events are not accessible in this collection.")
        else:
            self.authentication_note_var.set("")
        for child in self.observation_list.winfo_children():
            child.destroy()
        if not self.current_manifest:
            tk.Label(self.observation_list, text="Select or collect a real data set before exploring observations.", bg="#ffffff", fg="#627586", font=("Segoe UI", 9), wraplength=540, justify="left").pack(anchor="w", padx=9, pady=12)
            self.set_observation_detail(None)
            return
        if not self.observations:
            tk.Label(self.observation_list, text="The current repeat-pattern checks did not produce an observation. This does not prove that no security-relevant activity occurred.", bg="#ffffff", fg="#627586", font=("Segoe UI", 9), wraplength=540, justify="left").pack(anchor="w", padx=9, pady=12)
            self.set_observation_detail(None)
            return
        for observation in self.observations:
            card = self.make_observation_card(self.observation_list, observation)
            card.pack(fill="x", pady=(0, 8))
        if self.selected_observation:
            self.set_observation_detail(self.selected_observation)
        else:
            self.set_observation_detail(self.observations[0])

    def choose_observation(self, observation: dict[str, Any]) -> None:
        self.selected_observation = observation
        self.set_observation_detail(observation)

    def set_observation_detail(self, observation: dict[str, Any] | None) -> None:
        if not hasattr(self, "observation_detail"):
            return
        self.observation_detail.configure(state="normal")
        self.observation_detail.delete("1.0", "end")
        if not observation:
            self.observation_detail.insert("1.0", "Choose a collection and observation. Interpretations are kept separate from the evidence.")
        else:
            sample = observation.get("rows", [{}])[0]
            fields = {name: sample.get(name) for name in ("Timestamp", "Source", "Provider", "EventId", "Level", "RemoteAddress", "RemotePort", "ProcessName", "ProcessId") if sample.get(name) is not None}
            parts = [
                observation["title"],
                f"STATUS\n{observation['status']}  ·  {observation['category']}",
                f"WHAT WAS OBSERVED\n{observation['observed']}",
                f"WHAT THIS MEANS\n{observation['meaning']}",
                f"WHY IT IS SHOWN\n{observation['why']}",
                "EVIDENCE FIELDS\n" + (json.dumps(fields, indent=2, ensure_ascii=False) if fields else "No additional event fields are available."),
                f"WHAT WE DO NOT KNOW\nA repeat pattern alone does not establish intent, causation, or malicious activity. Review individual records and context.",
                "NEXT STEP\nInspect the supporting records, compare relevant timestamps, and identify what evidence is still missing.",
            ]
            self.observation_detail.insert("1.0", "\n\n".join(parts))
        self.observation_detail.configure(state="disabled")

    def view_observation_evidence(self, observation: dict[str, Any]) -> None:
        self.choose_observation(observation)
        self.source_var.set(observation.get("source", "All sources"))
        self.search_var.set(str(observation.get("rows", [{}])[0].get("EventId", "")))
        self.show_evidence()

    def open_observation_evidence(self) -> None:
        if self.selected_observation:
            self.view_observation_evidence(self.selected_observation)

    def render_patterns(self) -> None:
        self.build_observation_model()
        self.render_observations()
        self.render_overview()

    def start_investigation(self, observation: dict[str, Any] | None = None) -> None:
        observation = observation or self.selected_observation
        if not observation:
            messagebox.showinfo("Choose an observation", "Select an observation derived from the current collection before starting an investigation.", parent=self.root)
            return
        now = datetime.now(timezone.utc)
        base_dir = DATA_DIR / "investigations"
        base_dir.mkdir(parents=True, exist_ok=True)
        existing_numbers = []
        for path in base_dir.glob("INV-*.json"):
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                case_id = str(existing.get("case_id", ""))
                if case_id.startswith("INV-") and case_id[4:].isdigit():
                    existing_numbers.append(int(case_id[4:]))
            except (OSError, json.JSONDecodeError):
                continue
        next_number = max(existing_numbers, default=0) + 1
        case_id = f"INV-{next_number:03d}"
        while (base_dir / f"{case_id}.json").exists():
            next_number += 1
            case_id = f"INV-{next_number:03d}"
        evidence_rows = observation.get("rows", [])
        anchor = evidence_rows[0] if evidence_rows else {}
        evidence_refs = []
        for row in evidence_rows[:100]:
            evidence_refs.append({key: row.get(key) for key in ("_source_key", "Timestamp", "Source", "Provider", "EventId", "RecordId", "ProcessId", "RemoteAddress", "RemotePort") if row.get(key) is not None})
        relevant_fields = {
            key: anchor[key]
            for key in ("Timestamp", "Source", "Provider", "EventId", "RecordId", "Machine", "Level", "RemoteAddress", "RemotePort", "LocalAddress", "LocalPort", "ProcessName", "ProcessId", "Name", "StartTimeUtc")
            if anchor.get(key) is not None and anchor.get(key) != ""
        }
        facts = f"{observation['observed']}\nSource: {observation['source']}\nCollection: {getattr(self, 'current_collection_id', 'unknown')}"
        investigation = {
            "case_id": case_id,
            "title": observation.get("title", "Evidence review"),
            "created_at_utc": now.isoformat(),
            "status": "Open",
            "collection_id": getattr(self, "current_collection_id", None),
            "observation_key": observation["key"],
            "observation_title": observation["title"],
            "category": observation["category"],
            "source": observation.get("source"),
            "observed_summary": observation["observed"],
            "relevant_fields": relevant_fields,
            "observed_facts": facts,
            "interpretation": "",
            "unknown": "",
            "next_step": "",
            "evidence_references": evidence_refs,
        }
        self.write_investigation(investigation)
        self.selected_investigation = investigation
        self.load_investigations()
        self.render_investigations()
        self.show_investigations()

    def write_investigation(self, investigation: dict[str, Any]) -> None:
        path = DATA_DIR / "investigations" / f"{investigation['case_id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(investigation, indent=2, ensure_ascii=False), encoding="utf-8")

    def load_investigations(self) -> None:
        directory = DATA_DIR / "investigations"
        loaded = []
        if directory.exists():
            for path in sorted(directory.glob("INV-*.json"), reverse=True):
                try:
                    item = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(item, dict) and item.get("case_id"):
                    loaded.append(item)
        self.investigations = loaded
        if self.selected_investigation:
            selected_id = self.selected_investigation.get("case_id")
            self.selected_investigation = next((item for item in loaded if item.get("case_id") == selected_id), self.selected_investigation)

    def render_investigations(self) -> None:
        if not hasattr(self, "investigation_list"):
            return
        self.investigation_list.delete(0, "end")
        for item in self.investigations:
            self.investigation_list.insert("end", f"{item.get('case_id')}  ·  {item.get('title', 'Untitled')}")
        if not self.investigations:
            self.investigation_title_var.set("No investigation selected")
            self.investigation_observation_var.set("No cases are generated automatically. Select an evidence-derived observation, then choose Investigate to document your reasoning.")
            self.investigation_summary.set("No investigation has been created.")
            for editor in self.investigation_texts.values():
                editor.configure(state="normal")
                editor.delete("1.0", "end")
            if hasattr(self, "timeline_tree"):
                for item_id in self.timeline_tree.get_children():
                    self.timeline_tree.delete(item_id)
            return
        self.investigation_summary.set(f"{len(self.investigations)} analyst-authored investigation{'s' if len(self.investigations) != 1 else ''} saved locally.")
        selected_id = self.selected_investigation.get("case_id") if self.selected_investigation else None
        index = next((i for i, item in enumerate(self.investigations) if item.get("case_id") == selected_id), 0)
        self.investigation_list.selection_clear(0, "end")
        self.investigation_list.selection_set(index)
        self.investigation_list.activate(index)
        self.populate_investigation(self.investigations[index])

    def select_investigation(self, _event: tk.Event[Any]) -> None:
        selection = self.investigation_list.curselection()
        if not selection:
            return
        index = selection[0]
        if index < len(self.investigations):
            self.selected_investigation = self.investigations[index]
            self.populate_investigation(self.selected_investigation)

    def populate_investigation(self, investigation: dict[str, Any]) -> None:
        self.selected_investigation = investigation
        collection_id = investigation.get("collection_id")
        if collection_id and collection_id != getattr(self, "current_collection_id", None):
            collection_label = next((label for label, session_id in self.session_label_ids.items() if session_id == collection_id), None)
            if collection_label:
                self.session_var.set(collection_label)
                self.load_selected_session()
        self.investigation_title_var.set(f"{investigation.get('case_id')}  ·  {investigation.get('title')}")
        self.investigation_observation_var.set(
            f"{investigation.get('status')}  ·  {investigation.get('category')}  ·  "
            f"Collection {investigation.get('collection_id') or 'not recorded'}\n"
            f"Observation: {investigation.get('observed_summary', 'No linked observation') }"
        )
        for key, editor in self.investigation_texts.items():
            editor.delete("1.0", "end")
            editor.insert("1.0", investigation.get(key if key != "facts" else "observed_facts", ""))
        self.investigation_saved_var.set(f"Saved {investigation.get('created_at_utc', '')}")
        self.render_investigation_timeline(investigation)

    def mark_investigation_dirty(self) -> None:
        if self.selected_investigation:
            self.investigation_saved_var.set("Unsaved edits")

    def save_investigation(self) -> None:
        if not self.selected_investigation:
            messagebox.showinfo("No investigation selected", "Start an investigation from a real observation before saving notes.", parent=self.root)
            return
        investigation = self.selected_investigation
        investigation["observed_facts"] = self.investigation_texts["facts"].get("1.0", "end-1c").strip()
        investigation["interpretation"] = self.investigation_texts["interpretation"].get("1.0", "end-1c").strip()
        investigation["unknown"] = self.investigation_texts["unknown"].get("1.0", "end-1c").strip()
        investigation["next_step"] = self.investigation_texts["next_step"].get("1.0", "end-1c").strip()
        investigation["updated_at_utc"] = datetime.now(timezone.utc).isoformat()
        self.write_investigation(investigation)
        self.investigation_saved_var.set(f"Saved {investigation['updated_at_utc']}")
        self.load_investigations()

    def render_investigation_timeline(self, investigation: dict[str, Any]) -> None:
        for item_id in self.timeline_tree.get_children():
            self.timeline_tree.delete(item_id)
        observation = next((item for item in self.observations if item.get("key") == investigation.get("observation_key")), None)
        if not observation:
            self.timeline_tree.insert("", "end", values=("", "Evidence reference", "Open the linked saved collection to inspect records.", "Collection unavailable"))
            return
        related = self.related_evidence(observation)
        for index, (row, basis) in enumerate(related[:30]):
            source_name = self.source_labels.get(row.get("_source_key", ""), row.get("_source_key", ""))
            self.timeline_tree.insert("", "end", iid=str(index), values=(self.row_timestamp(row), source_name, self.row_summary(row), basis))
        if not related:
            self.timeline_tree.insert("", "end", values=("", "", "No related records were found by exact-field or time-window checks.", "No relationship inferred"))

    def related_evidence(self, observation: dict[str, Any]) -> list[tuple[dict[str, Any], str]]:
        anchor = observation.get("rows", [{}])[0]
        anchor_time = self.parse_timestamp(self.row_timestamp(anchor))
        anchor_pid = str(anchor.get("ProcessId")) if anchor.get("ProcessId") is not None else ""
        anchor_remote = str(anchor.get("RemoteAddress") or "")
        anchor_event = (anchor.get("_source_key"), str(anchor.get("EventId")))
        result: list[tuple[dict[str, Any], str]] = []
        seen: set[int] = set()
        for row in self.rows:
            basis = None
            row_event = (row.get("_source_key"), str(row.get("EventId")))
            if row_event == anchor_event and anchor_event[1] != "None":
                basis = "Same source and event ID"
            elif anchor_pid and str(row.get("ProcessId")) == anchor_pid:
                basis = f"Same process ID {anchor_pid}; causation not established"
            elif anchor_remote and str(row.get("RemoteAddress") or "") == anchor_remote:
                basis = f"Same remote address {anchor_remote}; causation not established"
            elif anchor_time:
                row_time = self.parse_timestamp(self.row_timestamp(row))
                if row_time and abs((row_time - anchor_time).total_seconds()) <= 900:
                    basis = "Temporal proximity only — relationship not established"
            if basis and id(row) not in seen:
                result.append((row, basis))
                seen.add(id(row))
        result.sort(key=lambda item: self.parse_timestamp(self.row_timestamp(item[0])) or datetime.min.replace(tzinfo=timezone.utc))
        return result

    @staticmethod
    def parse_timestamp(value: str) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def render_system(self) -> None:
        if not self.inventory:
            return
        if not hasattr(self, "system_access_tree"):
            return
        self.system_device_var.set(
            f"{self.inventory.get('Machine') or 'This computer'}  ·  {self.inventory.get('OperatingSystem') or 'Windows'}  ·  "
            f"PowerShell {self.inventory.get('PowerShellVersion') or 'unknown'}  ·  "
            f"{ 'Administrator' if self.inventory.get('Administrator') else 'Standard user' } session"
        )

    def start_capture(self) -> None:
        if self.capture_path or not self.inventory or not self.inventory.get("Administrator"):
            messagebox.showinfo("Packet capture", "pktmon capture requires this application to be run as Administrator.", parent=self.root)
            return
        if not messagebox.askyesno(
            "Start packet capture?",
            "This records packets seen on your network adapters until you stop it. Captures may contain private addresses and partial packet contents. The file is capped at 64 MB and stays in your local Windows profile. Start only for your own authorized activity.",
            parent=self.root,
        ):
            return
        captures = DATA_DIR / "packet-captures"
        captures.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = captures / f"capture-{stamp}.etl"
        self.start_capture_button.configure(state="disabled")
        self.status_var.set("Starting pktmon capture…")

        def worker() -> None:
            try:
                result = subprocess.run(
                    ["pktmon.exe", "start", "--capture", "--comp", "nics", "--pkt-size", "128", "--file-name", str(path), "--file-size", "64", "--log-mode", "circular"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
                )
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "pktmon could not start.")
                self.messages.put(("capture_started", path))
            except Exception as error:
                self.messages.put(("error", f"Could not start packet capture: {error}"))

        threading.Thread(target=worker, daemon=True).start()

    def stop_capture(self) -> None:
        path = self.capture_path
        if not path:
            return
        self.stop_capture_button.configure(state="disabled")
        self.status_var.set("Stopping capture and converting it to PCAPNG…")

        def worker() -> None:
            try:
                stopped = subprocess.run(["pktmon.exe", "stop"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False)
                if stopped.returncode != 0:
                    raise RuntimeError(stopped.stderr.strip() or stopped.stdout.strip() or "pktmon could not stop.")
                pcapng = path.with_suffix(".pcapng")
                converted = subprocess.run(["pktmon.exe", "etl2pcap", str(path), "--out", str(pcapng)], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90, check=False)
                if converted.returncode != 0:
                    result = f"Capture stopped. ETL saved at {path}. PCAPNG conversion did not succeed: {converted.stderr.strip() or converted.stdout.strip()}"
                else:
                    result = f"Capture saved.\nETL evidence: {path}\nPCAPNG copy for packet viewers: {pcapng}"
                self.messages.put(("capture_stopped", result))
            except Exception as error:
                self.messages.put(("error", f"Could not finish packet capture: {error}"))

        threading.Thread(target=worker, daemon=True).start()

    def on_close(self) -> None:
        if self.capture_path:
            if messagebox.askyesno("Capture is active", "Stop and save the active packet capture before closing?", parent=self.root):
                self.pending_close = True
                self.stop_capture()
            return
        self.root.destroy()


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("This telemetry lab currently collects data from Windows only.")
    root = tk.Tk()
    TelemetryLab(root)
    root.mainloop()


if __name__ == "__main__":
    main()
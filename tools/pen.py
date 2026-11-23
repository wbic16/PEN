#!/usr/bin/env python3
"""PEN v1 — Protect Every Neighbor, hub implementation.

Three seats, one tool (subcommands):
  census  (N, worker)  — build/refresh the per-user program registry from
                         what actually runs on this node.
  watch   (P, warrior) — compare live programs against the registry;
                         unexpected programs are quarantined (SIGSTOP,
                         reversible) and recorded. Termination exists as
                         a leg but fires only for executables named in
                         config terminate_exes (default: empty — the
                         charter names no program class for termination;
                         everything else is quarantine-and-report).
  audit   (E, religious) — verify watcher/registry/register agreement,
                         heal the watcher if it is down, write the audit
                         report, and publish register state to git.

State lives in phext files in the repo working copy:
  registry/<node>.phext  — the expected set (closed input set)
  register.phext         — append-only record of every PEN event

Enrollment (Will, 2026-11-23): "auto-enroll all programs present upon
first invocation." A host's registry is established by PEN's first
invocation on that host — every program present at that moment is
auto-enrolled as expected (the baseline), recorded as an `enroll`
register event. No quarantine actions happen during an enrollment run.
Only programs appearing AFTER the baseline are unexpected.

Phext: scrolls separated by 0x17; each scroll is key: value lines.
Coordinates are positional (scroll index), named in the scroll header.
"""
import json, os, signal, subprocess, sys, time
from datetime import datetime, timezone

SCROLL = "\x17"
EE_ANCHOR = 1795327200  # EE 1 begins 2026-11-22 00:00:00 CST

def ee_now():
    t = int(time.time())
    return (t - EE_ANCHOR) // 420 + 1 if t >= EE_ANCHOR else 0

def iso_now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def load_config(path):
    with open(path) as f:
        return json.load(f)

# ---------- phext helpers ----------
def read_scrolls(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        data = f.read()
    return [s for s in data.split(SCROLL) if s.strip()]

def write_scrolls(path, scrolls):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(SCROLL.join(scrolls))

def append_scroll(path, text):
    scrolls = read_scrolls(path)
    scrolls.append(text)
    write_scrolls(path, scrolls)
    return len(scrolls)  # 1-based index of the new scroll

def parse_scroll(text):
    d = {}
    for line in text.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            d[k.strip()] = v.strip()
    return d

def scroll_text(fields):
    return "\n".join(f"{k}: {v}" for k, v in fields) + "\n"

# ---------- live process snapshot (from /proc, no ps binary) ----------
def snapshot():
    uptime = float(open("/proc/uptime").read().split()[0])
    hz = os.sysconf("SC_CLK_TCK")
    procs = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            stat = open(f"/proc/{pid}/stat").read()
            # comm may contain spaces/parens; fields after last ')'
            rest = stat[stat.rfind(")") + 2:].split()
            state = rest[0]
            starttime = int(rest[19])
            age = uptime - starttime / hz
            uid = None
            for line in open(f"/proc/{pid}/status"):
                if line.startswith("Uid:"):
                    uid = int(line.split()[1]); break
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
                exe = exe.replace(" (deleted)", "")
            except OSError:
                exe = ""
            comm = stat[stat.find("(") + 1:stat.rfind(")")]
            procs.append({"pid": pid, "uid": uid, "exe": exe, "comm": comm,
                          "state": state, "age_s": round(age, 1)})
        except (OSError, ValueError, IndexError):
            continue
    return procs

def uid_name(uid):
    import pwd
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)

def ancestor_pids():
    pids, pid = set(), os.getpid()
    while pid and pid > 1:
        pids.add(pid)
        try:
            stat = open(f"/proc/{pid}/stat").read()
            pid = int(stat[stat.rfind(")") + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            break
    return pids

def systemctl_units(scope):
    cmd = ["systemctl"] + (["--user"] if scope == "user" else []) + \
          ["list-units", "--type=service", "--all", "--no-legend", "--plain"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    units = []
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            units.append(parts[0])
    return units

# ---------- census (N) ----------
def build_registry_scrolls(cfg):
    """Census the node and return (scrolls, entry_count) for its registry."""
    node = cfg["node"]
    procs = snapshot()
    exes = {}
    for p in procs:
        if p["exe"]:
            exes.setdefault((uid_name(p["uid"]), p["exe"]), 0)
            exes[(uid_name(p["uid"]), p["exe"])] += 1
    scrolls, n = [], 0
    def add(fields):
        nonlocal n; n += 1
        fields = [("coordinate", f"1.1.1/1.1.1/1.1.{n}")] + fields
        scrolls.append(scroll_text(fields))
    stamp = [("censused_at", iso_now()), ("ee", str(ee_now())), ("node", node)]
    for unit in sorted(systemctl_units("user")):
        add([("program", unit), ("kind", "user-service"), ("user", cfg["owner"])] + stamp)
    for unit in sorted(systemctl_units("system")):
        add([("program", unit), ("kind", "system-service"), ("user", "system")] + stamp)
    for (user, exe), count in sorted(exes.items()):
        add([("program", os.path.basename(exe)), ("kind", "process-exe"),
             ("user", user), ("exe", exe), ("seen_count", str(count))] + stamp)
    # PEN's own tools are expected by construction
    for tool in ("pen.py census", "pen.py watch", "pen.py audit"):
        add([("program", tool), ("kind", "pen"), ("user", cfg["owner"])] + stamp)
    return scrolls, n

def registry_path(cfg):
    return os.path.join(cfg["repo"], "registry", f"{cfg['node']}.phext")

def enrollment_recorded(cfg):
    """True if the register already holds an enroll event for this node."""
    reg = os.path.join(cfg["repo"], "register.phext")
    for s in read_scrolls(reg):
        d = parse_scroll(s)
        if d.get("event") == "enroll" and d.get("node") == cfg["node"]:
            return True
    return False

def append_enroll_event(cfg, entries, note):
    reg = os.path.join(cfg["repo"], "register.phext")
    return append_scroll(reg, scroll_text([
        ("event", "enroll"), ("seat", "N"), ("at", iso_now()),
        ("ee", str(ee_now())), ("node", cfg["node"]),
        ("entries", str(entries)), ("note", note)]))

def cmd_census(cfg):
    node = cfg["node"]
    scrolls, n = build_registry_scrolls(cfg)
    path = registry_path(cfg)
    write_scrolls(path, scrolls)
    reg = os.path.join(cfg["repo"], "register.phext")
    idx = append_scroll(reg, scroll_text([
        ("event", "census"), ("seat", "N"), ("at", iso_now()), ("ee", str(ee_now())),
        ("node", node), ("entries", str(n)),
        ("note", "registry rebuilt from live census; diff is the review")]))
    print(f"census: {n} registry entries -> {path}; register scroll {idx}")
    if not enrollment_recorded(cfg):
        idx = append_enroll_event(cfg, n,
            "auto-enrollment on first invocation (census): every program "
            "present is enrolled as expected (Will, 2026-11-23)")
        print(f"census: first invocation — enrollment recorded at register scroll {idx}")

# ---------- watch (P) ----------
def load_registry(cfg):
    path = os.path.join(cfg["repo"], "registry", f"{cfg['node']}.phext")
    exes, services = set(), set()
    for s in read_scrolls(path):
        d = parse_scroll(s)
        if d.get("kind") == "process-exe":
            exes.add((d.get("user"), d.get("exe")))
        elif d.get("kind") in ("user-service", "system-service"):
            services.add(d.get("program"))
    return exes, services

def cmd_watch(cfg):
    reg_path = os.path.join(cfg["repo"], "register.phext")
    # Enrollment (Will, 2026-11-23): the first invocation on a host
    # auto-enrolls every program present as the baseline. No registry
    # yet -> this run IS the enrollment; no quarantine actions.
    if not os.path.exists(registry_path(cfg)):
        scrolls, n = build_registry_scrolls(cfg)
        write_scrolls(registry_path(cfg), scrolls)
        idx = append_enroll_event(cfg, n,
            "auto-enrollment on first invocation: every program present "
            "is enrolled as expected (Will, 2026-11-23)")
        cyc = append_scroll(reg_path, scroll_text([
            ("event", "watch-cycle"), ("seat", "P"), ("at", iso_now()),
            ("ee", str(ee_now())), ("node", cfg["node"]),
            ("unexpected", "0"),
            ("note", "first invocation: auto-enrollment run; no quarantine "
                     "actions; watching begins next cycle")]))
        print(f"watch: no registry for {cfg['node']} — auto-enrolled {n} "
              f"entries (register scroll {idx}); cycle recorded at scroll {cyc}")
        return
    # A registry that predates the enrollment rule (e.g. aletheia-core's
    # v1 census registry) IS that host's first-invocation enrollment:
    # record the marker retroactively, once, preserving register history.
    if not enrollment_recorded(cfg):
        n = len(read_scrolls(registry_path(cfg)))
        idx = append_enroll_event(cfg, n,
            "retroactive marker: this registry was established by the v1 "
            "census (EE 210-212), which was this host's first invocation; "
            "enrollment rule inscribed 2026-11-23 (Will)")
        print(f"watch: retroactive enrollment marker recorded at register scroll {idx}")
    exes, _services = load_registry(cfg)
    mine = ancestor_pids()
    owner = cfg["owner"]
    min_age = cfg.get("quarantine_min_age_s", 45)
    terminate_exes = set(cfg.get("terminate_exes", []))
    events = []
    for p in snapshot():
        user = uid_name(p["uid"])
        if user != owner or not p["exe"] or p["pid"] in mine:
            continue
        if os.path.basename(p["exe"]) in ("pen.py",):
            continue
        if (user, p["exe"]) in exes:
            continue
        # unexpected program
        entry = [("event", "unexpected"), ("seat", "P"), ("at", iso_now()),
                 ("ee", str(ee_now())), ("node", cfg["node"]), ("user", user),
                 ("pid", str(p["pid"])), ("exe", p["exe"]), ("comm", p["comm"]),
                 ("age_s", str(p["age_s"])), ("state", p["state"])]
        if p["exe"] in terminate_exes:
            try:
                os.kill(p["pid"], signal.SIGTERM)
                entry += [("action", "terminate"), ("result", "SIGTERM sent")]
            except OSError as e:
                entry += [("action", "terminate"), ("result", f"failed: {e}")]
        elif p["age_s"] >= min_age and p["state"] not in ("T", "t"):
            try:
                os.kill(p["pid"], signal.SIGSTOP)
                entry += [("action", "quarantine"), ("result", "SIGSTOP; frozen for review")]
            except OSError as e:
                entry += [("action", "quarantine"), ("result", f"failed: {e}")]
        else:
            entry += [("action", "record-only"),
                      ("result", f"below quarantine age {min_age}s or already stopped")]
        idx = append_scroll(reg_path, scroll_text(entry))
        events.append((idx, entry))
    idx = append_scroll(reg_path, scroll_text([
        ("event", "watch-cycle"), ("seat", "P"), ("at", iso_now()),
        ("ee", str(ee_now())), ("node", cfg["node"]),
        ("unexpected", str(len(events))),
        ("note", "cycle complete")]))
    print(f"watch: cycle recorded at scroll {idx}; {len(events)} unexpected")
    for i, e in events:
        d = dict(e)
        print(f"  scroll {i}: {d.get('exe')} pid {d.get('pid')} -> {d.get('action')}")

# ---------- audit (E) ----------
def cmd_audit(cfg):
    repo = cfg["repo"]
    reg_path = os.path.join(repo, "register.phext")
    scrolls = [parse_scroll(s) for s in read_scrolls(reg_path)]
    problems, heals = [], []
    # completeness: every action entry carries the required fields
    required = {"event", "seat", "at", "ee", "node"}
    for i, d in enumerate(scrolls, 1):
        if not required.issubset(d):
            problems.append(f"register scroll {i} missing fields: {required - set(d)}")
    watches = [d for d in scrolls if d.get("event") == "watch-cycle"]
    if not watches:
        problems.append("no watch-cycle entries in register")
    else:
        last = watches[-1].get("at", "")
        age = (datetime.now(timezone.utc).astimezone() -
               datetime.fromisoformat(last)).total_seconds()
        if age > cfg.get("watch_max_stale_s", 900):
            problems.append(f"last watch cycle {int(age)}s ago (stale)")
            # healer: try to run a watch cycle now
            r = subprocess.run([sys.executable, os.path.abspath(__file__), "watch",
                                "--config", cfg["_path"]], capture_output=True, text=True)
            heals.append(f"ran watch cycle from audit: rc={r.returncode}")
            append_scroll(reg_path, scroll_text([
                ("event", "heal"), ("seat", "E"), ("at", iso_now()),
                ("ee", str(ee_now())), ("node", cfg["node"]),
                ("note", f"watch stale {int(age)}s; audit ran a cycle: rc={r.returncode}")]))
    # watcher timer state
    t = subprocess.run(["systemctl", "--user", "is-active", "pen-watch.timer"],
                       capture_output=True, text=True).stdout.strip()
    if t != "active":
        problems.append(f"pen-watch.timer is {t}")
        subprocess.run(["systemctl", "--user", "start", "pen-watch.timer"])
        heals.append("started pen-watch.timer")
    exes, services = load_registry(cfg)
    verdict = "CLEAN" if not problems else "FINDINGS"
    report = (f"# PEN audit — {cfg['node']}\n\n"
              f"- at: {iso_now()} (EE {ee_now()})\n- verdict: {verdict}\n"
              f"- register scrolls: {len(scrolls)}\n"
              f"- registry: {len(exes)} process exes, {len(services)} services\n"
              f"- watch cycles on record: {len(watches)}\n"
              f"- heals: {heals or 'none'}\n"
              f"- problems: {problems or 'none'}\n")
    rdir = os.path.join(repo, "reports")
    os.makedirs(rdir, exist_ok=True)
    day = datetime.now().strftime("%Y-%m-%d")
    with open(os.path.join(rdir, f"audit-{day}.md"), "a") as f:
        f.write(report + "\n")
    append_scroll(reg_path, scroll_text([
        ("event", "audit"), ("seat", "E"), ("at", iso_now()), ("ee", str(ee_now())),
        ("node", cfg["node"]), ("verdict", verdict),
        ("problems", str(len(problems))), ("heals", str(len(heals)))]))
    # publish: commit + push register/registry/reports if changed
    def git(*a):
        return subprocess.run(["git", "-C", repo] + list(a), capture_output=True, text=True)
    git("add", "register.phext", "registry", "reports")
    if git("status", "--porcelain").stdout.strip():
        git("commit", "-m", f"[pen] audit {day} EE {ee_now()}: {verdict.lower()}, "
                            f"{len(problems)} problems, {len(heals)} heals")
        push = git("push", "origin", "HEAD")
        print("audit: committed; push rc=", push.returncode, push.stderr.strip()[:200])
    print(f"audit: {verdict}; {len(problems)} problems; {len(heals)} heals; "
          f"register {len(scrolls)} scrolls")

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["census", "watch", "audit"])
    ap.add_argument("--config", required=True)
    a = ap.parse_args()
    cfg = load_config(a.config)
    cfg["_path"] = a.config
    {"census": cmd_census, "watch": cmd_watch, "audit": cmd_audit}[a.cmd](cfg)

if __name__ == "__main__":
    main()

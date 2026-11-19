"""Local WorkBuddy storage inventory and exact-file quarantine."""
import argparse
from collections import Counter
from datetime import date, datetime, timedelta
import hashlib
from html import escape
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

HOME = Path.home().resolve()
DATA = HOME / ".workbuddy"
ROOTS = [
    DATA, HOME / "WorkBuddy", Path("/Applications/WorkBuddy.app"),
    *(HOME / "Library" / name for name in (
        "Application Support/WorkBuddy", "Application Support/com.tencent.workbuddy.mac",
        "Caches/com.tencent.workbuddy.mac", "Caches/com.tencent.workbuddy.mac.BundleMigration",
        "WebKit/com.tencent.workbuddy.mac", "HTTPStorages/com.tencent.workbuddy.mac",
        "Preferences/com.tencent.workbuddy.mac.plist",
        "Containers/com.tencent.workbuddy.mac.WechatShare",
    )),
]
MIGRATION = HOME / "Library/Caches/com.tencent.workbuddy.mac.BundleMigration"
BACKUPS = MIGRATION / "backups"
BACKUP_NAME = re.compile(r"WorkBuddy-[0-9.]+-[0-9]+\.backup\.app")
LOG = re.compile(r"logs/(\d{4}-\d{2}-\d{2})/workbuddyMainThread__[0-9a-f]{32}\.log")
WORKSPACE = re.compile(r"\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}")


def safe_stat(path):
    if path.resolve(strict=True) != path:
        raise ValueError(f"拒绝链接路径 {path}")
    return path.lstat()


def fingerprint(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def eligible(path, info, days=14):
    match = LOG.fullmatch(path.relative_to(DATA).as_posix()) if path.is_relative_to(DATA) else None
    if not match or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return False
    try:
        cutoff = date.today() - timedelta(days=days)
        return date.fromisoformat(match[1]) < cutoff and datetime.fromtimestamp(info.st_mtime).date() < cutoff
    except ValueError:
        return False


def classify(path):
    if path == ROOTS[1] or path.parent == ROOTS[1]:
        return "L3"
    if path.name != "com.tencent.workbuddy.mac.BundleMigration" and (
        path.name in {"cache", "traces", "clipboard-images", "logs"}
        or path.parent in {DATA / "cache", HOME / "Library" / "Caches"}
    ):
        return "L2"
    if path.parent == DATA and path.name in {
        "workspace", "projects", "blobs", "artifact-index", "file-history",
        "file-tree-manifests", "storage", "changes-detail", "changes-index",
    }:
        return "L3"
    return "L4"


def backup_review(rows):
    """Recognize old rollback copies using bundle metadata and the latest install."""
    try:
        def version(bundle):
            plist = bundle / "Contents/Info.plist"
            safe_stat(plist)
            with plist.open("rb") as stream:
                info = plistlib.load(stream)
            if info["CFBundleIdentifier"] != "com.tencent.workbuddy.mac":
                raise ValueError("unexpected bundle identity")
            raw = info["CFBundleShortVersionString"]
            return raw, tuple(int(part) for part in raw.split("."))

        current, baseline = version(ROOTS[2])
        log = DATA / "logs/update/install-mac-bundle-update.log"
        safe_stat(log)
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 262144))
            tail = stream.read().decode(errors="replace")
        retained = re.findall(r"backup retained at (.+) for manual recovery", tail)
        events = [line for line in tail.splitlines()
                  if "updated app opened successfully" in line or "backup retained at " in line]
        if len(events) < 2 or "updated app opened successfully" not in events[-2]:
            return []
        verified = []
        for row in rows:
            path = Path(row["path"])
            if path.parent != BACKUPS or not BACKUP_NAME.fullmatch(path.name):
                continue
            if not retained or str(path) != retained[-1]:
                continue
            old, prior = version(path)
            if prior < baseline:
                verified.append(dict(path=str(path), allocated=row["allocated"],
                                     current=current, backup=old))
        return verified
    except (OSError, ValueError, KeyError, TypeError, plistlib.InvalidFileException):
        return []


def inventory(days=14):
    seen, rows, candidates, problems = set(), [], [], []
    dated, files, activity = [], Counter(), Counter()

    def measure(path, row):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            problems.append(f"跳过符号链接 {path}")
            return
        key = (info.st_dev, info.st_ino)
        if key in seen:
            return
        if stat.S_ISDIR(info.st_mode):
            seen.add(key)
            row["allocated"] += info.st_blocks * 512
            for child in sorted(path.iterdir()):
                attempt(child, row)
        elif stat.S_ISREG(info.st_mode):
            seen.add(key)
            row["allocated"] += info.st_blocks * 512
            row["logical"] += info.st_size
            row["files"] += 1
            for name in ("logs", "traces", "workspace"):
                if path.is_relative_to(DATA / name):
                    day = datetime.fromtimestamp(info.st_mtime).date().isoformat()
                    activity[(name, day)] += info.st_blocks * 512
                    break
            if eligible(path, info, days):
                candidates.append({"path": str(path), "identity": fingerprint(info),
                                   "allocated": info.st_blocks * 512})
            if path.is_relative_to(DATA / "projects") and path.suffix == ".jsonl":
                files["项目 JSONL 文件"] += 1
            if path.is_relative_to(DATA / "projects") and path.name.endswith(".file-rollback.ndjson"):
                files["回滚 NDJSON 文件"] += 1

    def attempt(path, row):
        try:
            measure(path, row)
        except OSError as exc:
            problems.append(str(exc))

    def add(path, own_only=False):
        row = dict(path=str(path), level=classify(path), allocated=0, logical=0, files=0)
        if own_only:
            row["allocated"] = path.lstat().st_blocks * 512
        else:
            attempt(path, row)
        rows.append(row)

    for root in ROOTS:
        try:
            safe_stat(root)
            if root in ROOTS[:2]:
                add_root = root.stat()
                rows.append(dict(path=str(root) + "（目录本身）", level=classify(root),
                                 allocated=add_root.st_blocks * 512, logical=0, files=0))
                for child in sorted(root.iterdir()):
                    if child == DATA / "cache" and child.is_dir() and not child.is_symlink():
                        add(child, own_only=True)
                        for entry in sorted(child.iterdir()):
                            add(entry)
                    else:
                        add(child)
            elif root == MIGRATION:
                add(root, own_only=True)
                for child in sorted(root.iterdir()):
                    if child == BACKUPS and stat.S_ISDIR(child.lstat().st_mode):
                        add(child, own_only=True)
                        for entry in sorted(child.iterdir()):
                            add(entry)
                    else:
                        add(child)
            else:
                add(root)
            if root == ROOTS[1]:
                dated = [dict(name=Path(row["path"]).name, allocated=row["allocated"])
                         for row in rows if Path(row["path"]).parent == root
                         and WORKSPACE.fullmatch(Path(row["path"]).name)
                         and Path(row["path"]).is_dir() and not Path(row["path"]).is_symlink()]
        except FileNotFoundError:
            if root in ROOTS[:2]:
                problems.append(f"未找到 {root}")
        except (OSError, ValueError) as exc:
            problems.append(str(exc))

    sessions = Counter()
    completed = set()
    try:
        db = DATA / "workbuddy.db"
        wal = db.with_name(db.name + "-wal")

        def snapshot_sources():
            sources = {db: fingerprint(safe_stat(db))}
            if wal.exists() or wal.is_symlink():
                sources[wal] = fingerprint(safe_stat(wal))
            return sources

        with tempfile.TemporaryDirectory(prefix="workbuddy-db-") as scratch:
            sources = snapshot_sources()
            for source in sources:
                shutil.copyfile(source, Path(scratch) / source.name)
            if snapshot_sources() != sources:
                raise ValueError("会话数据库在复制期间变化，请复扫")
            snapshot = Path(scratch) / db.name
            with sqlite3.connect(snapshot.as_uri() + "?mode=ro", uri=True, timeout=1) as conn:
                columns = {column[1] for column in conn.execute("PRAGMA table_info(sessions)")}
                if {"id", "status"} <= columns:
                    completed.update(row[0] for row in conn.execute(
                        "SELECT id FROM sessions WHERE lower(status) = 'completed'"))
                for created, deleted in conn.execute("SELECT created_at, deleted_at FROM sessions"):
                    try:
                        day = datetime.fromtimestamp(created / 1000).date().isoformat()
                    except (TypeError, ValueError, OverflowError, OSError):
                        day = "日期不可用"
                    sessions[(day, "未标记删除" if deleted is None else "已标记删除")] += 1
        session_status = "已读取本地数据库"
    except (OSError, sqlite3.Error, ValueError) as exc:
        sessions.clear()
        completed.clear()
        session_status = "会话统计不可用"
        problems.append(str(exc))

    backups = backup_review(rows)
    confirmed_paths = {item["path"] for item in backups}
    for row in rows:
        if row["path"] in confirmed_paths:
            row["level"] = "L2"

    return dict(rows=sorted(rows, key=lambda row: -row["allocated"]), dated=dated,
                sessions=[dict(day=day, state=state, count=count)
                          for (day, state), count in sorted(sessions.items(), reverse=True)],
                session_status=session_status, project_files=dict(files), problems=problems,
                backup_review=backups, completed_sessions=sorted(completed),
                activity=[dict(category=category, day=day, allocated=amount)
                          for (category, day), amount in sorted(activity.items(), reverse=True)]), candidates


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def mib(size):
    return f"{size / 1048576:,.2f} MiB"


def dashboard(report, candidates):
    rows = report["rows"]
    stats = Counter()
    for item in report["sessions"]:
        stats[item["state"]] += item["count"]
    largest = max((row["allocated"] for row in rows), default=1) or 1
    graph = "".join(
        f'<tr><td>{escape(row["path"])}</td><td>{row["level"]}</td>'
        f'<td><meter aria-label="相对占用" min="0" max="{largest}" value="{row["allocated"]}"></meter> '
        f'{mib(row["allocated"])}</td><td>{row["files"]:,}</td></tr>' for row in rows
    )
    peak = max((item["count"] for item in report["sessions"]), default=1)
    days = "".join(
        f'<tr><td>{item["day"]}</td><td>{item["state"]}</td>'
        f'<td><meter aria-label="相对会话数量" min="0" max="{peak}" value="{item["count"]}"></meter> '
        f'{item["count"]}</td></tr>' for item in report["sessions"]
    )
    overview = " · ".join(f"{key} {value}" for key, value in stats.items())
    details = "<br>".join(escape(line) for line in report["problems"]) or "无记录"
    workspaces = "<br>".join(f'{item["name"]} · {mib(item["allocated"])}' for item in report["dated"])
    backups = "".join(
        f'<li>{mib(item["allocated"])} · 旧版 {escape(item["backup"])} → 当前 {escape(item["current"])}'
        f'<br>{escape(item["path"])}</li>' for item in report["backup_review"]
    )
    recent = "".join(
        f'<tr><td>{item["day"]}</td><td>{item["category"]}</td><td>{mib(item["allocated"])}</td></tr>'
        for item in sorted(report["activity"], key=lambda item: item["day"], reverse=True)
        if item["day"] >= (date.today() - timedelta(days=7)).isoformat()
    )
    return f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>WorkBuddy 存储盘点</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f6f5;color:#18302c;font:15px/1.6 system-ui}}
main{{max-width:1100px;margin:auto;padding:clamp(16px,5vw,52px)}}h1{{font-size:clamp(28px,5vw,48px);line-height:1.15}}
section,details{{background:white;padding:20px;margin:16px 0;border:1px solid #dce6e2;border-radius:14px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}}strong{{display:block;font-size:24px}}
table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #e3ece9;text-align:left;padding:8px;overflow-wrap:anywhere}}
meter{{width:85px}}summary{{cursor:pointer}}</style><main>
<h1>WorkBuddy 存储盘点</h1><div>{escape(report["scanned_at"])}</div>
<div class="cards">
<section>已测磁盘占用<strong>{mib(sum(row["allocated"] for row in rows))}</strong>含安装包和本地数据</section>
<section>本地会话记录<strong>{sum(stats.values()) if report["session_status"] == "已读取本地数据库" else "未知"}</strong>{overview or report["session_status"]}</section>
<section>L1 旧诊断日志<strong>{mib(sum(item["allocated"] for item in candidates))}</strong>{len(candidates)} 个候选文件</section>
</div><section><h2>优先复核 · 更新回退备份</h2>
<p>匹配旧版应用标识、版本及最近一次成功升级记录。结束 WorkBuddy 与更新进程后，可手动移入废纸篓，保留恢复机会。</p>
{f"<ul>{backups}</ul>" if backups else "<p>当前没有识别到与成功升级记录相符的备份。</p>"}
</section><section><h2>最近 7 天的写入分布</h2><p>按文件最后修改日期归集当前占用。连续两次扫描的体积差才表示净增长。</p>
<table><thead><tr><th>修改日期</th><th>目录</th><th>当前占用</th></tr></thead><tbody>{recent}</tbody></table></section>
<section><h2>占用分布</h2><p>L1 旧诊断日志为 L2 日志目录内的子集。L2 中间数据 · L3 会话和产物 · L4 应用和状态。</p>
<table><thead><tr><th>路径</th><th>层级</th><th>分配空间</th><th>文件</th></tr></thead><tbody>{graph}</tbody></table></section>
<section><h2>会话创建日期</h2><p>{report["session_status"]} · {escape(" · ".join(f"{k} {v}" for k,v in report["project_files"].items()))}</p>
<table><thead><tr><th>日期</th><th>状态</th><th>记录数</th></tr></thead><tbody>{days}</tbody></table></section>
<details><summary>日期命名的默认工作区（{len(report["dated"])}）</summary>{workspaces}</details>
<details><summary>扫描盲区与跳过项（{len(report["problems"])}）</summary>{details}</details></main></html>'''


def scan(out, days=14):
    out = out.resolve()
    if any(out.is_relative_to(root) for root in ROOTS) or out.is_relative_to(HOME / ".Trash"):
        raise ValueError("请将报告输出到独立的工作目录")
    # Capture data before creating any report files.
    report, candidates = inventory(days)
    report["scanned_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    out.mkdir(mode=0o700)
    write_json(out / "inventory.json", report)
    write_json(out / "plan.json", dict(schema=1, created=time.time(), days=days, files=candidates))
    (out / "dashboard.html").write_text(dashboard(report, candidates), encoding="utf-8")
    print(out / "dashboard.html")


def read_plan(path):
    raw = path.read_bytes()
    plan = json.loads(raw)
    if plan["schema"] != 1 or not isinstance(plan["files"], list):
        raise ValueError("计划格式不受支持")
    return plan, hashlib.sha256(raw).hexdigest()


def check_closed():
    output = subprocess.check_output(
        ["/bin/ps", "-axww", "-o", "pid=", "-o", "command="],
        text=True, errors="replace",
    )
    blockers = []
    for line in output.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        pid, command = parts
        if re.search(r"(?i)WorkBuddy\.app/|/\.workbuddy/(?:binaries|app)/|install-mac-bundle-update\.sh", command):
            blockers.append(pid)
    if blockers:
        displayed = "、".join(blockers[:5])
        raise ValueError(f"检测到 {len(blockers)} 个 WorkBuddy 相关进程（PID {displayed}）。"
                         "请在 WorkBuddy 菜单使用退出（⌘Q），等待更新完成后重新扫描。")


def validated(item, days=14):
    path = Path(item["path"])
    info = safe_stat(path)
    if not eligible(path, info, days) or fingerprint(info) != item["identity"]:
        raise ValueError(f"文件已变更或不符合清理规则 {path}")
    return path, info


def apply(plan, digest, confirmed):
    if confirmed != digest:
        raise ValueError("计划摘要不匹配，请重新预览")
    if not 0 <= time.time() - plan["created"] <= 86400:
        raise ValueError("计划已过期，请重新扫描")
    if not plan["files"]:
        print("没有 L1 候选，未执行移动")
        return
    days = plan.get("days", 14)
    if type(days) is not int or not 1 <= days <= 365:
        raise ValueError("日志保留期必须为 1–365 天")
    check_closed()
    sources = [validated(item, days) for item in plan["files"]]
    if len({path for path, _ in sources}) != len(sources):
        raise ValueError("计划包含重复路径")
    trash = HOME / ".Trash"
    trash_info = safe_stat(trash)
    if not stat.S_ISDIR(trash_info.st_mode) or any(info.st_dev != trash_info.st_dev for _, info in sources):
        raise ValueError("废纸篓不可用或源文件跨卷")
    batch = Path(tempfile.mkdtemp(prefix="WorkBuddy-logs-", dir=trash))
    print(f"恢复批次 {batch}", flush=True)
    mapping = {f"{index:06d}-{path.name}": str(path)
               for index, (path, _) in enumerate(sources, start=1)}
    with (batch / "restore.json").open("x", encoding="utf-8") as journal:
        json.dump(mapping, journal, ensure_ascii=False, indent=2)
        journal.flush()
        os.fsync(journal.fileno())
    moved = 0
    for name, item in zip(mapping, plan["files"]):
        check_closed()
        path, info = validated(item, days)
        path.rename(batch / name)
        moved += info.st_blocks * 512
        print(f"已移动 {path}", flush=True)
    print(f"已移入废纸篓 {mib(moved)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "preview", "apply"):
        command = commands.add_parser(name)
        command.add_argument("path", type=Path)
        if name == "scan":
            command.add_argument("--days", type=int, choices=range(1, 366), default=14, metavar="1–365")
        if name == "apply":
            command.add_argument("sha256")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.exit(1, "当前版本支持 macOS 本地模式\n")
    try:
        if args.command == "scan":
            scan(args.path, args.days)
        else:
            plan, digest = read_plan(args.path)
            if args.command == "preview":
                for item in plan["files"]:
                    print(f'{mib(item["allocated"])}  {item["path"]}')
                print(f'候选 {len(plan["files"])} 个 · 总计 {mib(sum(i["allocated"] for i in plan["files"]))}')
                print(f"SHA256 {digest}")
            else:
                apply(plan, digest, args.sha256)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"操作停止：{exc}\n")


if __name__ == "__main__":
    main()

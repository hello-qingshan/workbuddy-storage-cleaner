"""Temporary localhost interface for WorkBuddy cleanup."""
from contextlib import redirect_stdout
from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlsplit
import webbrowser

import storage


def review_rollback(source):
    """Snapshot the recognized rollback subtree without following links."""
    info = storage.safe_stat(source)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("修改备份目录不可用")
    children = {path.name for path in source.iterdir()}
    if children != {"commits", "state.json"}:
        raise ValueError("未知的修改备份结构")
    if not (source / "commits").is_dir() or not (source / "state.json").is_file():
        raise ValueError("修改备份结构不完整")
    digest = hashlib.sha256()
    allocated = 0

    def visit(path):
        entry = path.lstat()
        if entry.st_dev != info.st_dev or not (stat.S_ISDIR(entry.st_mode) or
                (stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1)):
            raise ValueError("修改备份含链接、跨卷或特殊文件")
        digest.update(json.dumps([str(path.relative_to(source)), storage.fingerprint(entry)]).encode())
        if stat.S_ISDIR(entry.st_mode):
            return entry.st_blocks * 512 + sum(visit(child) for child in sorted(path.iterdir()))
        return entry.st_blocks * 512

    allocated = visit(source)
    return dict(path=str(source), allocated=allocated, identity=digest.hexdigest())


def rollback_options(completed):
    for session in completed:
        if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", session):
            continue
        source = storage.DATA / "workspace" / "sessions" / session / "modify_backup_v2"
        try:
            item = review_rollback(source)
        except (OSError, ValueError):
            continue
        if item["allocated"]:
            yield item


def move_reviewed(kind, item):
    storage.check_closed()
    report, _ = storage.inventory()
    source = Path(item["path"])
    info = storage.safe_stat(source)
    if kind == "rollback":
        current = rollback_options([source.parent.name] if source.parent.name in report["completed_sessions"] else [])
    else:
        current = (
            {**entry, "identity": storage.fingerprint(info)}
            for entry in report["backup_review"] if entry["path"] == str(source)
        )
    if item not in current:
        raise ValueError("项目状态已变化，请重新扫描")
    trash = storage.HOME / ".Trash"
    target = storage.safe_stat(trash)
    if not stat.S_ISDIR(info.st_mode) or not stat.S_ISDIR(target.st_mode) or info.st_dev != target.st_dev:
        raise ValueError("路径或卷不匹配")
    batch = Path(tempfile.mkdtemp(prefix=f"WorkBuddy-{kind}-", dir=trash))
    journal = batch / "restore.json"
    with journal.open("x", encoding="utf-8") as stream:
        json.dump({source.name: str(source)}, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    storage.check_closed()
    identity = (review_rollback(source)["identity"] if kind == "rollback"
                else storage.fingerprint(storage.safe_stat(source)))
    if identity != item["identity"]:
        raise ValueError("备份已变化，请重新扫描")
    source.rename(batch / source.name)
    print(f"已移动 {source.name}\n恢复映射 {journal}")


def main():
    if sys.platform != "darwin":
        raise SystemExit("当前版本支持 macOS 本地模式")
    token = secrets.token_urlsafe(32)
    previews = {}

    class Panel(BaseHTTPRequestHandler):
        # Browsers can open a speculative connection without sending a request.
        timeout = 3

        def log_message(self, *_):
            pass

        def reply(self, body, status=200):
            encoded = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            # Keep the Origin header on same-origin form posts.
            self.send_header("Referrer-Policy", "same-origin")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def trusted_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def page(self, days, notice=""):
            report, logs = storage.inventory(days)
            report["scanned_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
            options = []
            for item in report["backup_review"]:
                try:
                    identity = storage.fingerprint(storage.safe_stat(Path(item["path"])))
                except (OSError, ValueError):
                    continue
                options.append(("backup", {**item, "identity": identity}))
            options.extend(("log", item) for item in logs)
            options.extend(("rollback", item) for item in sorted(
                rollback_options(report["completed_sessions"]), key=lambda item: -item["allocated"]))
            reasons = {
                "backup": "已验证旧版回退包，移走会影响手动降级",
                "log": "超出保留期的主线程诊断日志",
                "rollback": "已完成会话的修改备份，移走会影响该会话的历史文件回滚",
            }
            key = secrets.token_urlsafe(24)
            now = time.time()
            for expired in [key for key, preview in previews.items() if now - preview["created"] > 3600]:
                del previews[expired]
            if len(previews) >= 32:
                del previews[next(iter(previews))]
            previews[key] = dict(options=options, days=days, created=now)
            choices = "".join(
                f'<label style="display:block;margin:10px 0;overflow-wrap:anywhere">'
                f'<input type="checkbox" name="pick" value="{idx}"> '
                f'<b>{storage.mib(item["allocated"])}</b> · '
                f'{reasons[kind]}'
                f'<br><small>{escape(item["path"])}</small></label>'
                for idx, (kind, item) in enumerate(options)
            )
            action = f'/{token}'
            try:
                storage.check_closed()
                blocker = ""
            except (ValueError, storage.subprocess.SubprocessError) as exc:
                blocker = str(exc)
            preflight = (
                f'<p role="alert" style="padding:12px;background:#fff1d6;border-radius:8px">'
                f'<strong>当前无法移动</strong>{escape(blocker)}</p>' if blocker else ""
            )
            controls = f"""
<section><h2>智能清理推荐</h2>
<p>保留近几天的主线程日志，便于排查近期故障。应用运行需要的是当前文件，旧日志的主要价值是回溯故障。近期崩溃或正在提交工单时，可以延长保留期。</p>
<form method="get" action="{action}">
<label>保留天数 <input name="days" type="number" min="1" max="365" value="{days}" required></label>
<button>重新扫描</button> <small>日常 7 天 · 排障 14 天 · 紧急腾空间 1 天</small>
</form>
{f'<pre style="white-space:pre-wrap" role="status">{escape(notice)}</pre>' if notice else ''}
<p><b>{len(options)} 项推荐</b> · {storage.mib(sum(item["allocated"] for _, item in options))}</p>
<form method="post" action="{action}">
<input type="hidden" name="key" value="{key}">
{preflight}
<fieldset {'disabled' if blocker else ''}><legend>勾选要移动的项目</legend>{choices or '<p>此保留期内暂无符合规则的项目。</p>'}</fieldset>
<p>退出 WorkBuddy 及更新程序后执行。文件移入废纸篓，实际腾出磁盘空间取决于废纸篓处置。</p>
<label><input type="checkbox" name="confirm" value="yes" required> 我确认移动所选项目，并接受版本降级、历史文件回滚或旧日志排查能力的影响。</label>
<p><button {'disabled' if blocker or not options else ''}>移入废纸篓并复扫</button></p></form>
<details><summary>需要保留或单独审查的项目</summary>
<p>运行时先核对在用版本。会话记录及最终产物保留原位，已完成会话的修改回滚副本仅在单独勾选后移动。追踪和会话缓存需要先验证引用及恢复影响。</p></details>
</section>"""
            html = storage.dashboard(report, logs)
            self.reply(html.replace("</div><section><h2>优先复核", "</div>" + controls +
                                    "<section><h2>优先复核", 1))

        def do_GET(self):
            url = urlsplit(self.path)
            if not self.trusted_host() or url.path != f"/{token}":
                return self.reply("页面不存在", 404)
            try:
                days = int(parse_qs(url.query).get("days", ["7"])[0])
                if not 1 <= days <= 365:
                    raise ValueError
            except ValueError:
                return self.reply("保留期应为 1–365 天", 400)
            self.page(days)

        def do_POST(self):
            expected = f"http://127.0.0.1:{self.server.server_port}"
            if not self.trusted_host() or self.path != f"/{token}":
                return self.reply("页面不存在", 404)
            if self.headers.get("Origin") != expected:
                return self.reply(
                    f'<p>请求来源无效，未执行清理。</p><p><a href="/{token}">'
                    '返回清理面板并重新选择</a></p>', 403
                )
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 65536:
                    raise ValueError("无效的确认表单")
                form = parse_qs(self.rfile.read(length).decode(), max_num_fields=4096)
                key = form.get("key", [""])[0]
                state = previews.get(key)
                if state is None or time.time() - state["created"] > 3600:
                    return self.page(7, "预览已过期或已提交。已重新扫描，请勾选后再确认。")
                if form.get("confirm") != ["yes"]:
                    return self.page(state["days"], "请勾选确认框后提交。")
                picks = sorted({int(value) for value in form.get("pick", [])})
                if not picks or picks[0] < 0 or picks[-1] >= len(state["options"]):
                    return self.page(state["days"], "请至少勾选一个有效项目。")
                selected = [state["options"][idx] for idx in picks]
                days = state["days"]
                del previews[key]
                output = StringIO()
                try:
                    with redirect_stdout(output):
                        storage.check_closed()
                        logs = [item for kind, item in selected if kind == "log"]
                        if logs:
                            storage.apply(dict(created=state["created"], days=days, files=logs),
                                          token, token)
                        for kind, item in selected:
                            if kind != "log":
                                move_reviewed(kind, item)
                except (OSError, ValueError, storage.subprocess.SubprocessError) as exc:
                    print(f"操作停止：{exc}", file=output)
                self.page(days, output.getvalue())
            except (OSError, ValueError, UnicodeError) as exc:
                self.reply(escape(str(exc)), 400)

    with HTTPServer(("127.0.0.1", 0), Panel) as server:
        url = f"http://127.0.0.1:{server.server_port}/{token}"
        print(f"清理面板 {url}\n保持此终端运行，按 Ctrl+C 退出。", flush=True)
        webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

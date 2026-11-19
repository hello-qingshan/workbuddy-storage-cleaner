# WorkBuddy 存储智能清理

面向 macOS 的 WorkBuddy 存储盘点与清理技能。它展示磁盘占用和会话日期，并在本地面板中提供清理候选。

支持确认后将旧主线程日志、经升级日志核验的旧版应用备份、已完成会话的修改备份移入废纸篓。移动会影响旧日志排查、版本回退或会话文件回滚。批次目录中提供恢复映射。

## 使用

需要 macOS 和 Python 3.10 或更高版本。在独立终端运行：

```bash
python3 workbuddy-deep-clean/scripts/panel.py
```

浏览器打开终端显示的地址。退出 WorkBuddy 后，重新扫描、选择项目并确认。面板服务随终端进程结束而停止。

静态扫描：

```bash
python3 workbuddy-deep-clean/scripts/storage.py scan ./storage-report --days 7
```

报告含本机路径与会话统计，请检查后再分享。文件移入废纸篓后，清空废纸篓才会释放相应空间。

当前版本聚焦磁盘存储，运行追踪、会话缓存和项目产物仍需人工审阅。

---
name: workbuddy-deep-clean
display_name: WorkBuddy 存储智能清理
display_name_en: WorkBuddy Storage Cleanup
description: 扫描 macOS 上 WorkBuddy 的存储、会话与中间文件，通过本地可视化面板推荐旧日志、升级备份和已完成会话的修改备份，确认后移入废纸篓。
description_zh: 查看 WorkBuddy 存储占用，复核并清理旧日志、升级备份及会话修改备份。
description_en: Inspect WorkBuddy storage and session age, then review and recoverably move old diagnostic logs on macOS.
version: "1.3.0"
author: 青山
examples_zh:
  - 扫描 WorkBuddy 的占用，展示会话和中间文件分布。
  - 为旧诊断日志生成清理计划，先给我预览。
examples_en:
  - Scan WorkBuddy storage and show the distribution of sessions and intermediate files.
  - Prepare a cleanup plan for old diagnostic logs and show me the preview first.
---

# WorkBuddy 存储智能清理

macOS 本地模式需要 Python 3.10+。

用户要求可视化推荐、调整保留期或勾选清理时，让用户在独立终端运行 `python3 "<技能目录绝对路径>/scripts/panel.py"`，终端会显示本地面板地址。保持终端运行，在浏览器查看占用与推荐。面板默认保留 7 天，输入 1–365 天复扫，用 ⌘Q 退出 WorkBuddy，等待更新程序结束，再重新扫描、逐项勾选并确认提交。已完成会话的修改备份需单独勾选，移走将影响该会话的历史文件回滚。面板完成移动后自动复扫并显示结果。面板关闭后重新启动会生成新地址。发布时保持面板与 storage.py 在同一目录。

用户只需要静态报告时，在技能目录运行 `python3 scripts/storage.py scan <新报告目录> [--days 7]`。报告目录由用户工作区提供，禁止选在扫描根内。云端或其他系统没有本地能力时，说明当前不支持。

1. **盘点**。先跑只读扫描，提供 dashboard.html 和日期汇总。优先展示有升级证据的旧版回退包和近七天写入分布。把自动日志候选数和手动清理候选分开汇报。会话按数据库创建时间统计，单列软删除记录。目录日期、文件修改时间和会话时间分别解释。
2. **分层**。L1 为符合规则的旧诊断日志。L2 为经证据核验的手动清理候选和仍需核验的中间数据。L3 为会话、产物和用户项目。L4 为应用、运行环境、账号状态和未知结构。按 [规则与生命周期](references/lifecycle.md) 解释分类证据。
3. **预览及确认**。`python3 scripts/storage.py preview <报告目录>/plan.json`。显示文件路径、体积、保留期和计划摘要。只在用户明确同意该计划后，提供从独立终端执行的完整命令 `python3 scripts/storage.py apply <计划绝对路径> <预览显示的 SHA256>`。从 WorkBuddy 内启动时只做到预览。退出客户端后才可执行。
4. **验证及恢复**。运行同一脚本的 `scan` 到新目录，对照成功移动清单和复扫结果。移动只转移占用，用户检查会话、产物和历史后可在废纸篓中自行处置。恢复方式见规则页。扫描报告和计划含本地路径，默认留在本机。

用户若指定项目中的脚本或图片，逐项核对产物与引用后给出人工审阅清单。未知来源、单凭日期、文件后缀或发现最终产物，均不得晋级为执行规则。

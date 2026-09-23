#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 supabase-setup.sql 同步进 sql-copy.html（一键复制页）。

用法：
    python sync-sql-copy.py

会原地更新 sql-copy.html 中：
  1. <div class="sub">…</div>  说明文字
  2. <pre id="sql">…</pre>     高亮展示用（HTML 转义）
  3. var SQL = "…";           一键复制用（json.dumps 转义）
"""
import html
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SQL_FILE = os.path.join(HERE, "supabase-setup.sql")
OUT_FILE = os.path.join(HERE, "sql-copy.html")

SUB_HTML = (
    '用途：为 Consultant Club 管理后台建表（<b>admins / sessions / submissions / '
    'consultants / project_interest / projects</b>）+ RLS 安全策略 + 登录/管理函数 + '
    '初始总管理员 + 现有 7 个项目种子数据。脚本幂等，重复执行无副作用。'
)


def main():
    with io.open(SQL_FILE, "r", encoding="utf-8") as f:
        sql = f.read()
    with io.open(OUT_FILE, "r", encoding="utf-8") as f:
        page = f.read()

    # 1. 说明文字
    page, n1 = re.subn(r'<div class="sub">.*?</div>', '<div class="sub">' + SUB_HTML + '</div>',
                       page, count=1, flags=re.S)

    # 2. <pre id="sql"> 展示块
    page, n2 = re.subn(r'(<pre id="sql">).*?(</pre>)',
                       lambda m: m.group(1) + html.escape(sql, quote=True) + m.group(2),
                       page, count=1, flags=re.S)

    # 3. var SQL = "…";   （用 lambda 避免替换串里的 \u 被当成转义）
    js_literal = 'var SQL = ' + json.dumps(sql, ensure_ascii=True) + ';'
    page, n3 = re.subn(r'^var SQL = .*$', lambda m: js_literal, page, count=1, flags=re.M)

    if not (n1 and n2 and n3):
        print("ERROR: 替换失败 sub=%d pre=%d var=%d" % (n1, n2, n3))
        return 1

    with io.open(OUT_FILE, "w", encoding="utf-8", newline="") as f:
        f.write(page)

    print("OK: %s -> %s  (%d chars of SQL)" % (os.path.basename(SQL_FILE),
                                               os.path.basename(OUT_FILE), len(sql)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

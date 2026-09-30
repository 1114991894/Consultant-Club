#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 supabase-setup.sql 同步进 sql-copy.html（一键复制页）。

用法：
    python sync-sql-copy.py

会原地更新 sql-copy.html 中：
  1. <div class="sub">…</div>                说明文字
  2. <pre id="sql">…</pre>                   全量脚本 · 高亮展示（HTML 转义）
  3. var SQL = "…";                         全量脚本 · 一键复制（json.dumps 转义）
  4. <pre id="sqlInc">…</pre>                「本次新增」增量段 · 高亮展示
  5. var SQL_INC = "…";                      「本次新增」增量段 · 一键复制

同时另外写出 supabase-resume.sql（只含增量段，方便单独执行）。
增量段 = 从 "-- ---------- 9." 开始到文件末尾
         （简历投递 + 管理员密码重置 + 咨询师账号体系）。
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
INC_FILE = os.path.join(HERE, "supabase-resume.sql")

INC_MARK = "-- ---------- 9."

SUB_HTML = (
    '用途：为 Consultant Club 建表（<b>admins / sessions / submissions / consultants / '
    'project_interest / projects / resumes / resume_parts / resume_downloads</b> 等）'
    '+ RLS 安全策略 + 登录 / 管理 / 项目 / 简历投递 / 密码重置 / 咨询师账号体系等函数 '
    '+ 初始总管理员 + 现有项目种子数据。'
    '脚本幂等，重复执行无副作用（不会 update / delete 任何已有数据）。'
)

# 增量段只执行这一段即可，无需重跑全量
INC_SQL = None


def split_inc(sql):
    i = sql.find(INC_MARK)
    if i < 0:
        return None
    # 往回收一行注释头（"-- ---------- 9. 简历投递…" 之前的空行归上一节）
    return sql[i:].lstrip("\n")


def main():
    with io.open(SQL_FILE, "r", encoding="utf-8") as f:
        sql = f.read()
    with io.open(OUT_FILE, "r", encoding="utf-8") as f:
        page = f.read()

    inc = split_inc(sql)
    if not inc:
        print("ERROR: 未在 %s 找到增量段标记 %r" % (os.path.basename(SQL_FILE), INC_MARK))
        return 1

    # 1. 说明文字
    page, n1 = re.subn(r'<div class="sub">.*?</div>', '<div class="sub">' + SUB_HTML + '</div>',
                       page, count=1, flags=re.S)

    # 2. <pre id="sql"> 展示块（全量）
    page, n2 = re.subn(r'(<pre id="sql">).*?(</pre>)',
                       lambda m: m.group(1) + html.escape(sql, quote=True) + m.group(2),
                       page, count=1, flags=re.S)

    # 3. var SQL = "…";
    js_literal = 'var SQL = ' + json.dumps(sql, ensure_ascii=True) + ';'
    page, n3 = re.subn(r'^var SQL = .*$', lambda m: js_literal, page, count=1, flags=re.M)

    # 4. <pre id="sqlInc"> 展示块（增量）
    page, n4 = re.subn(r'(<pre id="sqlInc">).*?(</pre>)',
                       lambda m: m.group(1) + html.escape(inc, quote=True) + m.group(2),
                       page, count=1, flags=re.S)

    # 5. var SQL_INC = "…";
    inc_literal = 'var SQL_INC = ' + json.dumps(inc, ensure_ascii=True) + ';'
    page, n5 = re.subn(r'^var SQL_INC = .*$', lambda m: inc_literal, page, count=1, flags=re.M)

    if not (n1 and n2 and n3 and n4 and n5):
        print("ERROR: 替换失败 sub=%d pre=%d var=%d preInc=%d varInc=%d" % (n1, n2, n3, n4, n5))
        return 1

    with io.open(OUT_FILE, "w", encoding="utf-8", newline="") as f:
        f.write(page)

    # 额外产出：只含增量段的独立 SQL 文件
    with io.open(INC_FILE, "w", encoding="utf-8", newline="") as f:
        f.write(inc)

    print("OK: %s -> %s  (full %d chars / inc %d chars)" % (
        os.path.basename(SQL_FILE), os.path.basename(OUT_FILE), len(sql), len(inc)))
    print("OK: %s written (%d chars)" % (os.path.basename(INC_FILE), len(inc)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

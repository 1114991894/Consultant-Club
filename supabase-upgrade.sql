-- ============================================================
-- Consultant Club 管理后台 · 数据库升级脚本（处理功能）
-- 用法：在 Supabase SQL Editor 中直接 Run
-- ============================================================

-- 给 submissions 表增加处理相关字段
alter table public.submissions add column if not exists status text not null default 'pending' check (status in ('pending','handled'));
alter table public.submissions add column if not exists handler_phone text;
alter table public.submissions add column if not exists handler_name text;
alter table public.submissions add column if not exists handled_at timestamptz;
alter table public.submissions add column if not exists notes text;

-- 索引：按状态过滤
create index if not exists submissions_status_idx on public.submissions (status);

-- ---------- 新 RLS 策略：管理员可更新自己的处理记录 ----------
drop policy if exists submissions_admin_update on public.submissions;
create policy submissions_admin_update on public.submissions
  for update to anon, authenticated using (
    admin_from_token(current_setting('request.headers', true)::json->>'x-admin-token') is not null
  ) with check (
    admin_from_token(current_setting('request.headers', true)::json->>'x-admin-token') is not null
  );

-- ---------- 新增业务函数 ----------

-- 标记为已处理 / 未处理（带处理人留痕）
create or replace function public.admin_mark_status(
  p_token text,
  p_submission_id uuid,
  p_status text,
  p_notes text default null
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_sub public.submissions;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if p_status not in ('pending', 'handled') then
    return json_build_object('ok', false, 'error', '状态值无效');
  end if;
  select * into v_sub from public.submissions where id = p_submission_id;
  if v_sub.id is null then
    return json_build_object('ok', false, 'error', '记录不存在');
  end if;
  update public.submissions
     set status       = p_status,
         handler_phone = v_admin.phone,
         handler_name  = v_admin.name,
         handled_at    = case when p_status = 'handled' then now() else null end,
         notes         = coalesce(p_notes, notes)
   where id = p_submission_id;
  return json_build_object('ok', true);
end;
$$;

-- 添加/更新联系记录
create or replace function public.admin_add_note(
  p_token text,
  p_submission_id uuid,
  p_notes text
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_sub public.submissions;
  v_prefix text;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if p_notes is null or length(trim(p_notes)) = 0 then
    return json_build_object('ok', false, 'error', '记录内容不能为空');
  end if;
  select * into v_sub from public.submissions where id = p_submission_id;
  if v_sub.id is null then
    return json_build_object('ok', false, 'error', '记录不存在');
  end if;
  v_prefix := '[' || v_admin.name || ' ' || to_char(now(), 'YYYY-MM-DD HH24:MI') || '] ';
  update public.submissions
     set notes = coalesce(notes, '') || E'\n' || v_prefix || trim(p_notes)
   where id = p_submission_id;
  return json_build_object('ok', true);
end;
$$;

-- 查询未处理数量（用于角标）
create or replace function public.admin_unread_counts(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  return json_build_object('ok', true, 'counts', (
    select json_build_object(
      'book', (select count(*) from public.submissions where type='book' and status='pending'),
      'apply', (select count(*) from public.submissions where type='apply' and status='pending')
    )
  ));
end;
$$;
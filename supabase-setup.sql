-- ============================================================
-- Consultant Club 管理后台 · Supabase 初始化脚本
-- 用法：登录 https://supabase.com/dashboard → 选择本项目
--       → 左侧 SQL Editor → 粘贴全部内容 → Run
-- 可重复执行（幂等）
-- ============================================================

create extension if not exists pgcrypto with schema extensions;
create extension if not exists "uuid-ossp" with schema extensions;

-- ---------- 1. 数据表 ----------

-- 管理员表（总管理员 role=super / 普通管理员 role=admin）
create table if not exists public.admins (
  id            uuid primary key default extensions.uuid_generate_v4(),
  phone         text unique not null,
  password_hash text not null,
  name          text,
  role          text not null default 'admin' check (role in ('super','admin')),
  created_at    timestamptz not null default now()
);

-- 登录会话（token 7 天有效）
create table if not exists public.sessions (
  token      text primary key,
  admin_id   uuid not null references public.admins(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

-- 表单提交收集表（type: book=预约诊断 / apply=咨询师申请）
create table if not exists public.submissions (
  id         uuid primary key default extensions.uuid_generate_v4(),
  type       text not null check (type in ('book','apply')),
  data       jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists submissions_created_idx on public.submissions (created_at desc);
create index if not exists submissions_type_idx    on public.submissions (type);

-- ---------- 2. 辅助函数（先于 RLS，因 RLS 策略会引用 admin_from_token） ----------

-- 根据 token 取当前管理员（内部辅助）
create or replace function public.admin_from_token(p_token text)
returns public.admins
language sql stable security definer set search_path = public, extensions as $$
  select a.* from public.sessions s
  join public.admins a on a.id = s.admin_id
  where s.token = p_token and s.expires_at > now()
  limit 1
$$;

-- ---------- 3. RLS（行级安全） ----------

alter table public.admins      enable row level security;
alter table public.sessions    enable row level security;
alter table public.submissions enable row level security;

-- admins / sessions 不开放任何直接访问策略（全部拒绝，仅安全函数内部可操作）

-- 任何人可提交表单
drop policy if exists submissions_insert_anon on public.submissions;
create policy submissions_insert_anon on public.submissions
  for insert to anon, authenticated with check (true);

-- 携带有效 x-admin-token 请求头的管理员可读取
drop policy if exists submissions_admin_read on public.submissions;
create policy submissions_admin_read on public.submissions
  for select to anon, authenticated using (
    admin_from_token(current_setting('request.headers', true)::json->>'x-admin-token') is not null
  );

-- ---------- 4. 业务函数 ----------

-- 登录：手机号 + 密码 → token
create or replace function public.admin_login(p_phone text, p_password text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_token text;
begin
  delete from public.sessions where expires_at < now();
  select * into v_admin from public.admins where phone = p_phone limit 1;
  if v_admin.id is null or v_admin.password_hash <> crypt(p_password, v_admin.password_hash) then
    return json_build_object('ok', false, 'error', '手机号或密码错误');
  end if;
  v_token := encode(extensions.gen_random_bytes(32), 'hex');
  insert into public.sessions (token, admin_id, expires_at)
  values (v_token, v_admin.id, now() + interval '7 days');
  return json_build_object('ok', true, 'token', v_token,
    'role', v_admin.role, 'phone', v_admin.phone, 'name', v_admin.name);
end;
$$;

-- 修改自己的密码
create or replace function public.admin_change_password(p_token text, p_old text, p_new text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if v_admin.password_hash <> crypt(p_old, v_admin.password_hash) then
    return json_build_object('ok', false, 'error', '原密码不正确');
  end if;
  if p_new is null or length(p_new) < 6 then
    return json_build_object('ok', false, 'error', '新密码至少 6 位');
  end if;
  update public.admins set password_hash = crypt(p_new, gen_salt('bf')) where id = v_admin.id;
  delete from public.sessions where admin_id = v_admin.id and token <> p_token;
  return json_build_object('ok', true);
end;
$$;

-- 总管理员：列出所有管理员
create or replace function public.admin_list(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if v_admin.role <> 'super' then
    return json_build_object('ok', false, 'error', '仅总管理员可操作');
  end if;
  return json_build_object('ok', true, 'admins', (
    select coalesce(json_agg(json_build_object(
      'id', a.id, 'phone', a.phone, 'name', a.name,
      'role', a.role, 'created_at', a.created_at) order by a.created_at), '[]'::json)
    from public.admins a
  ));
end;
$$;

-- 总管理员：添加管理员
create or replace function public.admin_create(p_token text, p_phone text, p_password text, p_name text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if v_admin.role <> 'super' then
    return json_build_object('ok', false, 'error', '仅总管理员可操作');
  end if;
  if p_phone is null or p_phone !~ '^1\d{10}$' then
    return json_build_object('ok', false, 'error', '手机号格式不正确');
  end if;
  if p_password is null or length(p_password) < 6 then
    return json_build_object('ok', false, 'error', '初始密码至少 6 位');
  end if;
  if exists (select 1 from public.admins where phone = p_phone) then
    return json_build_object('ok', false, 'error', '该手机号已存在');
  end if;
  insert into public.admins (phone, password_hash, name, role)
  values (p_phone, crypt(p_password, gen_salt('bf')), nullif(trim(p_name), ''), 'admin');
  return json_build_object('ok', true);
end;
$$;

-- 总管理员：删除管理员（不能删自己和总管理员）
create or replace function public.admin_delete(p_token text, p_admin_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if v_admin.role <> 'super' then
    return json_build_object('ok', false, 'error', '仅总管理员可操作');
  end if;
  if p_admin_id = v_admin.id then
    return json_build_object('ok', false, 'error', '不能删除自己');
  end if;
  if exists (select 1 from public.admins where id = p_admin_id and role = 'super') then
    return json_build_object('ok', false, 'error', '不能删除总管理员');
  end if;
  delete from public.admins where id = p_admin_id;
  return json_build_object('ok', true);
end;
$$;

-- ---------- 5. 初始化总管理员 ----------
-- 手机号：13634169539    初始密码：liu123456
insert into public.admins (phone, password_hash, name, role)
values ('13634169539', crypt('liu123456', gen_salt('bf')), '总管理员', 'super')
on conflict (phone) do nothing;
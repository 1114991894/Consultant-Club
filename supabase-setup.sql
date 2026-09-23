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

-- 总管理员：删除提交记录（预约诊断 / 咨询师申请）
create or replace function public.admin_delete_submission(p_token text, p_submission_id uuid)
returns json
language plpgsql security definer set search_path = public as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if v_admin.role <> 'super' then
    return json_build_object('ok', false, 'error', '仅总管理员可操作');
  end if;
  delete from public.submissions where id = p_submission_id;
  if not found then
    return json_build_object('ok', false, 'error', '记录不存在或已删除');
  end if;
  return json_build_object('ok', true);
end;
$$;

-- 批量上传合并：管理员将新字段补入现有提交（p_data 仅含需补入的键），并追加备注
create or replace function public.admin_merge_submission(
  p_token text, p_submission_id uuid, p_data jsonb, p_note text
)
returns json
language plpgsql security definer set search_path = public as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  update public.submissions
     set data = case when p_data is not null and p_data <> '{}'::jsonb
                     then data || p_data else data end,
         notes = case when coalesce(p_note, '') <> ''
                      then coalesce(notes, '') ||
                           case when coalesce(notes, '') <> '' then chr(10) else '' end || p_note
                      else notes end
   where id = p_submission_id;
  if not found then
    return json_build_object('ok', false, 'error', '记录不存在');
  end if;
  return json_build_object('ok', true);
end;
$$;

-- ---------- 5. 项目「感兴趣」计数（每个 IP 每个项目限一次） ----------
create table if not exists public.project_interest (
  id         uuid primary key default gen_random_uuid(),
  project_id text not null,
  ip_hash    text not null,
  created_at timestamptz not null default now(),
  unique (project_id, ip_hash)
);
alter table public.project_interest enable row level security;
-- 不开放直接访问，仅通过安全函数操作

-- 查询某项目的感兴趣人数
create or replace function public.project_interest_count(p_project_id text)
returns json
language sql stable security definer set search_path = public as $$
  select json_build_object('ok', true, 'count', (
    select count(*) from public.project_interest where project_id = p_project_id
  ));
$$;

-- 点击：按 IP 去重（IP 哈希脱敏存储，重复点击不增减计数）
create or replace function public.project_interest_vote(p_project_id text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_raw_ip text;
  v_ip     text;
  v_hash   text;
begin
  v_raw_ip := coalesce(
    current_setting('request.headers', true)::json->>'x-forwarded-for', '');
  v_ip := btrim(split_part(v_raw_ip, ',', 1));
  if v_ip is null or v_ip = '' then
    v_ip := 'unknown';
  end if;
  v_hash := encode(digest('cc_salt_2026:' || v_ip, 'sha256'), 'hex');
  insert into public.project_interest (project_id, ip_hash)
  values (p_project_id, v_hash)
  on conflict (project_id, ip_hash) do nothing;
  return json_build_object('ok', true,
    'count', (select count(*) from public.project_interest where project_id = p_project_id),
    'first', found);
end;
$$;

-- ---------- 5. 初始化总管理员 ----------
-- 手机号：13634169539    初始密码：liu123456
insert into public.admins (phone, password_hash, name, role)
values ('13634169539', crypt('liu123456', gen_salt('bf')), '总管理员', 'super')
on conflict (phone) do nothing;

-- ---------- 6. 咨询师管理（首页「项目咨询师」动态化） ----------

-- 咨询师表：image 存前端裁剪压缩后的 base64（400x400 JPEG，约 30-80KB）
create table if not exists public.consultants (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  title text not null default '',
  bio text not null default '',
  image text not null default '',
  sort bigint not null default (extract(epoch from now()) * 1000)::bigint,
  created_at timestamptz not null default now()
);

alter table public.consultants enable row level security;
drop policy if exists "consultants_public_read" on public.consultants;
create policy "consultants_public_read" on public.consultants
  for select to anon, authenticated using (true);

-- 新增 / 编辑（需登录 token；p_image 传空字符串表示保留原图）
create or replace function public.consultant_save(
  p_token text, p_id uuid, p_name text, p_title text, p_bio text, p_image text
)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_row public.consultants;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  p_name := btrim(coalesce(p_name, ''));
  p_title := btrim(coalesce(p_title, ''));
  if p_name = '' or p_title = '' then
    return json_build_object('ok', false, 'error', '姓名与头衔为必填');
  end if;
  if p_id is null then
    if coalesce(p_image, '') = '' then
      return json_build_object('ok', false, 'error', '请上传人物图像');
    end if;
    insert into public.consultants (name, title, bio, image)
    values (p_name, p_title, coalesce(p_bio, ''), p_image)
    returning * into v_row;
  else
    update public.consultants set
      name = p_name, title = p_title, bio = coalesce(p_bio, ''),
      image = case when coalesce(p_image, '') = '' then image else p_image end
    where id = p_id
    returning * into v_row;
    if v_row.id is null then
      return json_build_object('ok', false, 'error', '记录不存在');
    end if;
  end if;
  return json_build_object('ok', true, 'id', v_row.id);
end;
$$;

-- 删除（需登录 token）
create or replace function public.consultant_delete(p_token text, p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  delete from public.consultants where id = p_id;
  if not found then
    return json_build_object('ok', false, 'error', '记录不存在或已删除');
  end if;
  return json_build_object('ok', true);
end;
$$;

-- 上移 / 下移（与相邻记录交换 sort 值）
create or replace function public.consultant_move(p_token text, p_id uuid, p_dir text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_cur public.consultants;
  v_nb  public.consultants;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  select * into v_cur from public.consultants where id = p_id;
  if v_cur.id is null then
    return json_build_object('ok', false, 'error', '记录不存在');
  end if;
  if p_dir = 'up' then
    select * into v_nb from public.consultants
      where sort < v_cur.sort order by sort desc limit 1;
  else
    select * into v_nb from public.consultants
      where sort > v_cur.sort order by sort asc limit 1;
  end if;
  if v_nb.id is null then
    return json_build_object('ok', true, 'moved', false);
  end if;
  update public.consultants set sort = v_nb.sort where id = v_cur.id;
  update public.consultants set sort = v_cur.sort where id = v_nb.id;
  return json_build_object('ok', true, 'moved', true);
end;
$$;

-- ---------- 7. 项目管理（官网「最近咨询项目」动态化） ----------

-- 项目表：profile/challenges/steps 存 JSON，顺序即前端展示顺序
--   profile    = [{"k":"企业性质","v":"民营制造企业"}, ...]
--   challenges = [{"t":"挑战小标题","d":"一句话说明"}, ...]
--   steps      = [{"t":"步骤标题（／表示换行）","d":"这一步做什么"}, ...]
create table if not exists public.projects (
  id          uuid primary key default gen_random_uuid(),
  project_id  text unique not null,
  category    text not null default 'growth',
  industry    text not null default '',
  tech_tag    text not null default '',
  period      text not null default '',
  status_text text not null default '询单中',
  title       text not null default '',
  subtitle    text not null default '',
  profile     jsonb not null default '[]'::jsonb,
  challenges  jsonb not null default '[]'::jsonb,
  steps       jsonb not null default '[]'::jsonb,
  value_title text not null default '项目价值',
  value_desc  text not null default '',
  sort        bigint not null default (extract(epoch from now()) * 1000)::bigint,
  published   boolean not null default false,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create index if not exists projects_pub_sort_idx on public.projects (published, sort desc);

alter table public.projects enable row level security;

-- 公开读：前端只读「已发布」的项目
drop policy if exists projects_public_read on public.projects;
create policy projects_public_read on public.projects
  for select to anon, authenticated using (published = true);

-- 列表（后台用，含未发布）
create or replace function public.project_list(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  return json_build_object('ok', true, 'projects', (
    select coalesce(json_agg(json_build_object(
      'id', pr.id, 'project_id', pr.project_id, 'category', pr.category,
      'industry', pr.industry, 'tech_tag', pr.tech_tag, 'period', pr.period,
      'status_text', pr.status_text, 'title', pr.title, 'subtitle', pr.subtitle,
      'profile', pr.profile, 'challenges', pr.challenges, 'steps', pr.steps,
      'value_title', pr.value_title, 'value_desc', pr.value_desc,
      'sort', pr.sort, 'published', pr.published,
      'created_at', pr.created_at, 'updated_at', pr.updated_at
    ) order by pr.sort desc, pr.created_at desc), '[]'::json)
    from public.projects pr
  ));
end;
$$;

-- 保存（p_id 为空=新建，否则=编辑）；所有管理员可操作
create or replace function public.project_save(p_token text, p_id uuid, p_data jsonb)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_row   public.projects;
  v_pid   text;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if p_data is null then
    return json_build_object('ok', false, 'error', '项目数据为空');
  end if;
  v_pid := btrim(coalesce(p_data->>'project_id', ''));
  if v_pid = '' then
    return json_build_object('ok', false, 'error', '项目ID不能为空');
  end if;
  if btrim(coalesce(p_data->>'title', '')) = '' then
    return json_build_object('ok', false, 'error', '项目标题不能为空');
  end if;

  if p_id is null then
    if exists (select 1 from public.projects where project_id = v_pid) then
      return json_build_object('ok', false, 'error', '项目ID「' || v_pid || '」已存在');
    end if;
    insert into public.projects (
      project_id, category, industry, tech_tag, period, status_text,
      title, subtitle, profile, challenges, steps,
      value_title, value_desc, published
    ) values (
      v_pid,
      coalesce(nullif(p_data->>'category', ''), 'growth'),
      coalesce(p_data->>'industry', ''),
      coalesce(p_data->>'tech_tag', ''),
      coalesce(p_data->>'period', ''),
      coalesce(nullif(p_data->>'status_text', ''), '询单中'),
      btrim(p_data->>'title'),
      coalesce(p_data->>'subtitle', ''),
      coalesce(p_data->'profile', '[]'::jsonb),
      coalesce(p_data->'challenges', '[]'::jsonb),
      coalesce(p_data->'steps', '[]'::jsonb),
      coalesce(nullif(p_data->>'value_title', ''), '项目价值'),
      coalesce(p_data->>'value_desc', ''),
      coalesce((p_data->>'published')::boolean, false)
    ) returning * into v_row;
  else
    if exists (select 1 from public.projects where project_id = v_pid and id <> p_id) then
      return json_build_object('ok', false, 'error', '项目ID「' || v_pid || '」已被其他项目占用');
    end if;
    update public.projects set
      project_id  = v_pid,
      category    = coalesce(nullif(p_data->>'category', ''), category),
      industry    = coalesce(p_data->>'industry', industry),
      tech_tag    = coalesce(p_data->>'tech_tag', tech_tag),
      period      = coalesce(p_data->>'period', period),
      status_text = coalesce(nullif(p_data->>'status_text', ''), status_text),
      title       = btrim(p_data->>'title'),
      subtitle    = coalesce(p_data->>'subtitle', subtitle),
      profile     = coalesce(p_data->'profile', profile),
      challenges  = coalesce(p_data->'challenges', challenges),
      steps       = coalesce(p_data->'steps', steps),
      value_title = coalesce(nullif(p_data->>'value_title', ''), value_title),
      value_desc  = coalesce(p_data->>'value_desc', value_desc),
      published   = coalesce((p_data->>'published')::boolean, published),
      updated_at  = now()
    where id = p_id
    returning * into v_row;
    if v_row.id is null then
      return json_build_object('ok', false, 'error', '记录不存在');
    end if;
  end if;
  return json_build_object('ok', true, 'id', v_row.id, 'project_id', v_row.project_id);
end;
$$;

-- 删除（仅总管理员）
create or replace function public.project_delete(p_token text, p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if v_admin.role <> 'super' then
    return json_build_object('ok', false, 'error', '仅总管理员可删除项目');
  end if;
  delete from public.projects where id = p_id;
  if not found then
    return json_build_object('ok', false, 'error', '记录不存在或已删除');
  end if;
  return json_build_object('ok', true);
end;
$$;

-- 发布 / 取消发布
create or replace function public.project_set_publish(p_token text, p_id uuid, p_pub boolean)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_row   public.projects;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  update public.projects
     set published = coalesce(p_pub, published), updated_at = now()
   where id = p_id
   returning * into v_row;
  if v_row.id is null then
    return json_build_object('ok', false, 'error', '记录不存在');
  end if;
  return json_build_object('ok', true, 'published', v_row.published);
end;
$$;

-- 上移 / 下移（与相邻记录交换 sort；前端按 sort 倒序，越靠上越前）
create or replace function public.project_move(p_token text, p_id uuid, p_dir text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_cur   public.projects;
  v_nb    public.projects;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  select * into v_cur from public.projects where id = p_id;
  if v_cur.id is null then
    return json_build_object('ok', false, 'error', '记录不存在');
  end if;
  if p_dir = 'up' then
    select * into v_nb from public.projects
      where sort > v_cur.sort order by sort asc limit 1;
  else
    select * into v_nb from public.projects
      where sort < v_cur.sort order by sort desc limit 1;
  end if;
  if v_nb.id is null then
    return json_build_object('ok', true, 'moved', false);
  end if;
  update public.projects set sort = v_nb.sort where id = v_cur.id;
  update public.projects set sort = v_cur.sort where id = v_nb.id;
  return json_build_object('ok', true, 'moved', true);
end;
$$;

-- ---------- 8. 现有 7 个项目种子（幂等：project_id 已存在则跳过） ----------
-- 目的：让前端从「写死在 HTML」平滑切到「读数据库」时视觉零变化

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published)
values
('p001', 'growth', '汽车零部件 / 精密制造', '生产数字化', '2026.09-2026.12', '询单中',
 '滚针轴承制造企业：打通生产数据链路，重建质量追溯体系',
 '为一家主机配套 + 出口双轮驱动的轴承制造企业，破解「系统孤岛、追溯断链」的生产数字化困局',
 '[{"k":"企业性质","v":"民营制造企业"},{"k":"主营产品","v":"变速箱轴承、曲轴连杆滚针轴承"},{"k":"业务结构","v":"主机厂配套 + 约 40% 出口"},{"k":"年产能","v":"3000 万套以上"}]'::jsonb,
 '[{"t":"两套系统各自为政，数据孤岛","d":"管家婆管经营、快工单管生产，订单、物料、工单、产出、库存互不相通，业务流与生产流脱节。"},{"t":"质量追溯停在「结果层」","d":"不良品只能看到结果，无法定位到具体工序、设备、人员与工艺参数，改善无从下手。"},{"t":"电镀工序后数据断联","d":"关键外协工序数据缺失，一条完整生产链路被拦腰截断，全程数据靠人工补救。"},{"t":"系统流程与生产实际不符","d":"首检、巡检、提前抽检等真实质量动作无法在系统中完成，系统反而变成负担。"},{"t":"设备有自动化、没数据化","d":"机床自动化基础良好，但设备未联网，缺少 SCADA / MES 层数据采集能力。"}]'::jsonb,
 '[{"t":"现场调研／流程还原","d":"驻场摸清真实生产逻辑与断点，输出问题清单"},{"t":"数据链路／打通方案","d":"双系统集成 + 电镀外协断点补齐，一次规划"},{"t":"设备联网／数据采集","d":"机床联网改造，补齐 SCADA / MES 采集层"},{"t":"质量追溯／上线陪跑","d":"按首检/巡检/抽检重构质检流程，陪跑到跑通"}]'::jsonb,
 '项目价值',
 '一条完整、可追溯的数字化生产链路：从订单到工序到成品，质量责任定位到工序、设备与人员，数据不再靠人工搬运。',
 7000, true)
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published)
values
('p002', 'growth', '新材料 / 健康科技', '市场增长', '2026.10-2027.06', '询单中',
 '碳纳米管柔性加热科技企业：搭建精准获客与 OEM/ODM 订单转化体系',
 '为一家手握硬核技术、却被「获客」卡住的新材料企业，补上从产品到订单的市场增长引擎',
 '[{"k":"企业性质","v":"民营科技制造企业"},{"k":"核心技术","v":"碳纳米管薄膜柔性加热"},{"k":"业务模式","v":"自有产品 + OEM/ODM 定制"},{"k":"目标行业","v":"健康理疗 / 服装户外 / 家居礼品 / 消费电子"}]'::jsonb,
 '[{"t":"客户渠道有限，缺稳定 B2B 来源","d":"品牌方、渠道商、采购商等精准客户开发依赖现有资源和零散机会，没有持续获客通道。"},{"t":"OEM/ODM 订单零散，难成气候","d":"研发、开模、定制能力俱全，但缺少标准化的获客、需求承接与订单转化体系。"},{"t":"产品多，但产品—客户—渠道不匹配","d":"加热眼罩、护膝、马甲、披毯、玩偶对应不同场景与客群，重点产品、重点行业、重点渠道待明确。"}]'::jsonb,
 '[{"t":"产品×场景×渠道／匹配矩阵","d":"梳理产品线，锁定重点产品与重点行业"},{"t":"目标客户画像／获客通道搭建","d":"建立 B2B 精准客户持续获取的稳定通道"},{"t":"询盘承接／转化 SOP","d":"OEM/ODM 需求承接与订单转化的标准流程"},{"t":"AI 获客工具／部署陪跑","d":"工具上线、指标复盘，陪跑到达产"}]'::jsonb,
 '项目价值',
 '从「等订单」到「有体系地拿订单」：清晰的重点产品、重点行业与重点渠道，加一套可复制的 OEM/ODM 转化流程。',
 6000, true)
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published)
values
('p003', 'strategy', '连锁餐饮 / 消费服务', '多品牌扩张', '2026.11-2027.05', '询单中',
 '区域连锁餐饮集团：新品牌战略定位与扩张路径设计',
 '为一家多品牌区域连锁餐饮集团，理清「下一个五年靠什么增长」的战略命题',
 '[{"k":"企业性质","v":"连锁餐饮管理企业"},{"k":"现有业务","v":"成熟西餐连锁品牌运营"},{"k":"区域布局","v":"区域深耕，辐射周边市场"},{"k":"核心诉求","v":"新品牌孵化与集团化扩张"}]'::jsonb,
 '[{"t":"增长依赖单品牌，第二曲线模糊","d":"主品牌进入成熟期，新品牌方向多次试水未形成清晰定位，资源投放心里有底、手上没谱。"},{"t":"单店盈利模型未跑通就谈复制","d":"门店模型、人效与坪效标准不统一，扩张节奏缺乏数据支撑。"},{"t":"集团管控跟不上多品牌节奏","d":"总部与门店权责不清，供应链与人才供给难以支撑多线扩张。"}]'::jsonb,
 '[{"t":"战略诊断／增长意图澄清","d":"盘点资源禀赋，聚焦战略方向"},{"t":"新品牌定位／单店模型验证","d":"锁定细分赛道，打磨可复制盈利模型"},{"t":"扩张路径／与节奏设计","d":"分阶段增长路径与资源投放组合"},{"t":"集团管控／落地陪跑","d":"总部—门店权责与人才供给体系搭好"}]'::jsonb,
 '项目价值',
 '一套「定位—模型—复制」的扩张操作系统：新品牌有据可依，扩张节奏有数可算，集团管控有人可用。',
 5000, true)
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published)
values
('p004', 'perf', '产业园区运营', '全国多园区', '2026.10-2026.12', '询单中',
 '产业园区运营服务商：全国园区全维度绩效管理体系设计',
 '为一家布局全国多个园区的运营服务商，把「招商转化、租金收缴、空置控制」装进一套考核体系',
 '[{"k":"企业性质","v":"产业园区运营服务商"},{"k":"业务规模","v":"全国多城市园区布局"},{"k":"核心业务","v":"园区开发运营 + 企业服务"},{"k":"核心诉求","v":"统一考核，激活招商"}]'::jsonb,
 '[{"t":"考核「走形式」，指标与业务脱节","d":"现有考核停留在出勤与主观评价，招商转化率、租金收缴率、空置率等关键结果未进入指标体系。"},{"t":"园区间差异大，一把尺子量不准","d":"不同园区处于入驻周期不同阶段，统一标准失真、分园标准难服众。"},{"t":"考核结果与激励脱钩","d":"干好干坏差别不大，招商骨干动力不足，目标达成缺少机制保障。"}]'::jsonb,
 '[{"t":"业务指标／体系梳理","d":"从园区经营结果倒推考核指标"},{"t":"分园差异化／指标设计","d":"按园区周期阶段定制权重与基线"},{"t":"考核激励／联动机制","d":"结果与奖金、晋升强挂钩"},{"t":"试运行／复盘校准","d":"小范围试点后全国推广"}]'::jsonb,
 '项目价值',
 '一套覆盖全国园区的绩效操作系统：关键指标进考核、考核结果进激励，招商目标达成有机制兜底。',
 4000, true)
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published)
values
('p005', 'org', '电商零售', '组织效能', '2026.12-2027.06', '询单中',
 '电商企业：业绩扩张期的组织架构重塑与人才梯队建设',
 '为一家处于规模跃升期的电商企业，解决「业务翻倍、组织没跟上」的扩张阵痛',
 '[{"k":"企业性质","v":"综合电商企业"},{"k":"业务规模","v":"多仓布局、全国发货"},{"k":"团队规模","v":"数百人，一线为主"},{"k":"核心诉求","v":"组织先于业务准备好"}]'::jsonb,
 '[{"t":"架构随业务长歪，权责含糊","d":"部门设置沿革多于设计，跨部门协作靠人情，关键流程无人端到端负责。"},{"t":"一线人才选拔培训不成体系","d":"业务扩张快于人才供给，新人合格率波动大，执行质量不稳定。"},{"t":"人效看不见、算不清","d":"缺少人效模型与数据看板，人力成本增长快于营收增长。"}]'::jsonb,
 '[{"t":"组织诊断／架构再设计","d":"按业务价值链重排部门与权责"},{"t":"岗位梳理／人效模型","d":"关键岗位再设计，建立人效基线"},{"t":"人才选拔／培训体系","d":"标准化选育用留，稳定一线质量"},{"t":"流程优化／数据看板","d":"流程提效上线，人效月度复盘"}]'::jsonb,
 '项目价值',
 '在不扩张人力成本的前提下托住业绩跃升：架构清晰、人效可算、一线执行质量稳定。',
 3000, true)
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published)
values
('p006', 'talent', '新能源材料', '人才体系', '2027.01-2027.06', '询单中',
 '新能源材料企业：关键岗位胜任力模型与人才画像体系搭建',
 '为一家快速扩张的新材料企业，把「招不准、育不出、留不住」的人才难题变成一套标准',
 '[{"k":"企业性质","v":"新能源电池材料企业"},{"k":"产业布局","v":"国内外多基地运营"},{"k":"发展阶段","v":"产能与技术双扩张期"},{"k":"核心诉求","v":"关键岗位选人有标准"}]'::jsonb,
 '[{"t":"关键岗位没有人才标准","d":"选人靠面试官个人经验，同一岗位不同面试官结论迥异，错招成本高。"},{"t":"招聘合格率不稳定","d":"到岗后表现与面试评估偏差大，试用期淘汰消耗团队精力。"},{"t":"梯队断层，晋升无路径","d":"骨干晋升靠资历排队，高潜人才看不到成长地图，流失风险积聚。"}]'::jsonb,
 '[{"t":"人才定位／标准共创","d":"与业务共定关键岗位人才标准"},{"t":"胜任力模型／人才画像","d":"能力项行为化，画像可评估"},{"t":"嵌入招聘／合格率验证","d":"画像落地招聘流程，跟踪合格率"},{"t":"发展路径／梯队地图","d":"晋升路径与培养计划成体系"}]'::jsonb,
 '项目价值',
 '让关键岗位「选人有尺、育人有梯、晋升有图」：招聘合格率可验证，高潜人才看得见未来。',
 2000, true)
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published)
values
('p007', 'training', '服饰零售', '销售铁军', '2026.10-2026.12', '询单中',
 '服饰集团销售分公司：「百万销冠」高绩效训练营',
 '为一家服饰集团区域分公司，把「靠个别高手出单」变成「人人有打法、店店有销冠」',
 '[{"k":"企业性质","v":"服饰集团区域分公司"},{"k":"团队构成","v":"多门店一线销售团队"},{"k":"业务特征","v":"线下成交为主、客单差异大"},{"k":"核心诉求","v":"销售业绩整体拉升"}]'::jsonb,
 '[{"t":"业绩靠高手，不靠体系","d":"少数销冠贡献大半业绩，打法沉淀不下来，人一走业绩就塌。"},{"t":"中间层能力断档","d":"大量一线销售停留在「等客上门」，缺乏主动成交与连单能力。"},{"t":"培训听过就忘，落不了地","d":"过往培训缺少实战演练与后续跟踪，行为改变几乎为零。"}]'::jsonb,
 '[{"t":"销冠打法／萃取建模","d":"把高手经验变成可教的打法库"},{"t":"实战训练营／分组对抗","d":"场景演练 + 通关考核，练到会为止"},{"t":"AI 陪练／日常固化","d":"智能体陪练嵌入日常，持续练兵"},{"t":"业绩追踪／复盘迭代","d":"训练期业绩对比复盘，打法迭代"}]'::jsonb,
 '项目价值',
 '销冠经验资产化、训练日常化：团队整体成交能力上台阶，业绩不再系于个别人。',
 1000, true)
on conflict (project_id) do nothing;
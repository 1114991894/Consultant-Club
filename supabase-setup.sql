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
  -- 密码同步记录一份明文，供总管理员在后台查看（表在第 10 节创建，调用时已存在）
  insert into public.admin_password_notes (admin_id, password_plain)
  values (v_admin.id, p_new)
  on conflict (admin_id) do update set password_plain = excluded.password_plain, updated_at = now();
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
      'role', a.role, 'password', n.password_plain,
      'created_at', a.created_at) order by a.created_at), '[]'::json)
    from public.admins a
    left join public.admin_password_notes n on n.admin_id = a.id
    where a.role <> 'consultant'          -- 咨询师账号不在「管理员管理」里展示
  ));
end;
$$;

-- 总管理员：添加管理员
create or replace function public.admin_create(p_token text, p_phone text, p_password text, p_name text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins; v_new uuid;
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
  values (p_phone, crypt(p_password, gen_salt('bf')), nullif(trim(p_name), ''), 'admin')
  returning id into v_new;
  -- 初始密码同步记录一份明文，供总管理员在后台查看（表在第 10 节创建，调用时已存在）
  insert into public.admin_password_notes (admin_id, password_plain)
  values (v_new, p_password)
  on conflict (admin_id) do update set password_plain = excluded.password_plain, updated_at = now();
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

-- 首次发布时间 / 最近一次再次发布时间：决定前端排序与 NEW / 更新 角标
--   first_pub_at 为空  = 从未发布过
--   last_pub_at > first_pub_at = 修改后再次发布过（前端显示「更新」）
alter table public.projects add column if not exists first_pub_at timestamptz;
alter table public.projects add column if not exists last_pub_at  timestamptz;

-- 回填历史数据：已发布但缺发布时间的，按项目编号给出递增的首发时间
--   p001 = 1 天前、p002 = 2 天前 …… 编号越大首发越早
--   前端按「首发时间倒序」排列 → p001 排最前，与原静态页顺序完全一致
update public.projects
   set first_pub_at = now() - greatest(coalesce(nullif(regexp_replace(project_id, '\D', '', 'g'), '')::int, 1), 1) * interval '1 day'
 where published = true and first_pub_at is null;

update public.projects set last_pub_at = first_pub_at where last_pub_at is null;

create index if not exists projects_first_pub_idx on public.projects (published, first_pub_at desc nulls last);

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
      'first_pub_at', pr.first_pub_at, 'last_pub_at', pr.last_pub_at,
      'created_at', pr.created_at, 'updated_at', pr.updated_at
    ) order by pr.first_pub_at desc nulls last, pr.created_at desc), '[]'::json)
    from public.projects pr
  ));
end;
$$;

-- 保存（p_id 为空=新建，否则=编辑）；所有管理员可操作
--   编号唯一：只要编号已被任何项目占用（前端存在且未删除），就拒绝保存/发布
--   首发时间：第一次发布时写入，之后不再变
--   最近发布：内容有改动且处于已发布状态时刷新 → 前端显示「更新」
create or replace function public.project_save(p_token text, p_id uuid, p_data jsonb)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin   public.admins;
  v_row     public.projects;
  v_old     public.projects;
  v_pid     text;
  v_pub     boolean;
  v_oldcon  jsonb;
  v_newcon  jsonb;
  v_changed boolean := false;
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
    return json_build_object('ok', false, 'error', '项目编号不能为空');
  end if;
  if btrim(coalesce(p_data->>'title', '')) = '' then
    return json_build_object('ok', false, 'error', '项目标题不能为空');
  end if;
  v_pub := coalesce((p_data->>'published')::boolean, false);

  if p_id is null then
    if exists (select 1 from public.projects where lower(project_id) = lower(v_pid)) then
      return json_build_object('ok', false,
        'error', '编号「' || v_pid || '」已被占用（该项目仍在前端展示，未删除），请换一个编号');
    end if;
    insert into public.projects (
      project_id, category, industry, tech_tag, period, status_text,
      title, subtitle, profile, challenges, steps,
      value_title, value_desc, published, first_pub_at, last_pub_at
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
      v_pub,
      case when v_pub then now() end,
      case when v_pub then now() end
    ) returning * into v_row;
  else
    select * into v_old from public.projects where id = p_id;
    if v_old.id is null then
      return json_build_object('ok', false, 'error', '记录不存在');
    end if;
    if exists (select 1 from public.projects
                where lower(project_id) = lower(v_pid) and id <> p_id) then
      return json_build_object('ok', false,
        'error', '编号「' || v_pid || '」已被其他项目使用，编号不可重复，请更换后再保存');
    end if;

    -- 内容是否真的改过（用于判断「修改后再次发布」）
    v_oldcon := jsonb_build_object(
      'category',    v_old.category,    'industry',    v_old.industry,
      'tech_tag',    v_old.tech_tag,    'period',      v_old.period,
      'status_text', v_old.status_text, 'title',       v_old.title,
      'subtitle',    v_old.subtitle,    'profile',     v_old.profile,
      'challenges',  v_old.challenges,  'steps',       v_old.steps,
      'value_title', v_old.value_title, 'value_desc',  v_old.value_desc);
    v_newcon := jsonb_build_object(
      'category',    coalesce(nullif(p_data->>'category', ''), v_old.category),
      'industry',    coalesce(p_data->>'industry', v_old.industry),
      'tech_tag',    coalesce(p_data->>'tech_tag', v_old.tech_tag),
      'period',      coalesce(p_data->>'period', v_old.period),
      'status_text', coalesce(nullif(p_data->>'status_text', ''), v_old.status_text),
      'title',       btrim(p_data->>'title'),
      'subtitle',    coalesce(p_data->>'subtitle', v_old.subtitle),
      'profile',     coalesce(p_data->'profile', v_old.profile),
      'challenges',  coalesce(p_data->'challenges', v_old.challenges),
      'steps',       coalesce(p_data->'steps', v_old.steps),
      'value_title', coalesce(nullif(p_data->>'value_title', ''), v_old.value_title),
      'value_desc',  coalesce(p_data->>'value_desc', v_old.value_desc));
    v_changed := v_oldcon is distinct from v_newcon;

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
      published   = v_pub,
      first_pub_at = case
        when v_pub and first_pub_at is null then now()
        else first_pub_at end,
      last_pub_at  = case
        when v_pub and first_pub_at is null then now()   -- 首次发布
        when v_pub and v_changed           then now()    -- 修改后再次发布
        when v_pub and not v_old.published then now()    -- 撤下后重新发布
        else last_pub_at end,
      updated_at  = now()
    where id = p_id
    returning * into v_row;
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

-- 发布 / 取消发布（同步维护首发时间与最近发布时间）
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
     set published = coalesce(p_pub, published),
         first_pub_at = case
           when coalesce(p_pub, published) and first_pub_at is null then now()
           else first_pub_at end,
         last_pub_at  = case
           when coalesce(p_pub, published) and first_pub_at is null then now()  -- 首次发布
           when coalesce(p_pub, published) and not published then now()         -- 撤下后重新发布
           else last_pub_at end,
         updated_at = now()
   where id = p_id
   returning * into v_row;
  if v_row.id is null then
    return json_build_object('ok', false, 'error', '记录不存在');
  end if;
  return json_build_object('ok', true, 'published', v_row.published);
end;
$$;

-- 手动排序已废弃：前端顺序改为「首次发布时间倒序」自动决定（越晚首发越靠前）
drop function if exists public.project_move(text, uuid, text);

-- ---------- 8. 现有 7 个项目种子（幂等：project_id 已存在则跳过） ----------
-- 目的：让前端从「写死在 HTML」平滑切到「读数据库」时视觉零变化
-- 首发时间按编号递增往前推（p001 最新 → 排最前），与原静态页顺序一致
-- 注意：last_pub_at 与 first_pub_at 相等 → 首装不带「更新」角标

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published,
   first_pub_at, last_pub_at)
values
('p001', 'growth', '汽车零部件 / 精密制造', '生产数字化', '2026.09-2026.12', '询单中',
 '滚针轴承制造企业：打通生产数据链路，重建质量追溯体系',
 '为一家主机配套 + 出口双轮驱动的轴承制造企业，破解「系统孤岛、追溯断链」的生产数字化困局',
 '[{"k":"企业性质","v":"民营制造企业"},{"k":"主营产品","v":"变速箱轴承、曲轴连杆滚针轴承"},{"k":"业务结构","v":"主机厂配套 + 约 40% 出口"},{"k":"年产能","v":"3000 万套以上"}]'::jsonb,
 '[{"t":"两套系统各自为政，数据孤岛","d":"管家婆管经营、快工单管生产，订单、物料、工单、产出、库存互不相通，业务流与生产流脱节。"},{"t":"质量追溯停在「结果层」","d":"不良品只能看到结果，无法定位到具体工序、设备、人员与工艺参数，改善无从下手。"},{"t":"电镀工序后数据断联","d":"关键外协工序数据缺失，一条完整生产链路被拦腰截断，全程数据靠人工补救。"},{"t":"系统流程与生产实际不符","d":"首检、巡检、提前抽检等真实质量动作无法在系统中完成，系统反而变成负担。"},{"t":"设备有自动化、没数据化","d":"机床自动化基础良好，但设备未联网，缺少 SCADA / MES 层数据采集能力。"}]'::jsonb,
 '[{"t":"现场调研／流程还原","d":"驻场摸清真实生产逻辑与断点，输出问题清单"},{"t":"数据链路／打通方案","d":"双系统集成 + 电镀外协断点补齐，一次规划"},{"t":"设备联网／数据采集","d":"机床联网改造，补齐 SCADA / MES 采集层"},{"t":"质量追溯／上线陪跑","d":"按首检/巡检/抽检重构质检流程，陪跑到跑通"}]'::jsonb,
 '项目价值',
 '一条完整、可追溯的数字化生产链路：从订单到工序到成品，质量责任定位到工序、设备与人员，数据不再靠人工搬运。',
 7000, true, now() - interval '1 day', now() - interval '1 day')
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published,
   first_pub_at, last_pub_at)
values
('p002', 'growth', '新材料 / 健康科技', '市场增长', '2026.10-2027.06', '询单中',
 '碳纳米管柔性加热科技企业：搭建精准获客与 OEM/ODM 订单转化体系',
 '为一家手握硬核技术、却被「获客」卡住的新材料企业，补上从产品到订单的市场增长引擎',
 '[{"k":"企业性质","v":"民营科技制造企业"},{"k":"核心技术","v":"碳纳米管薄膜柔性加热"},{"k":"业务模式","v":"自有产品 + OEM/ODM 定制"},{"k":"目标行业","v":"健康理疗 / 服装户外 / 家居礼品 / 消费电子"}]'::jsonb,
 '[{"t":"客户渠道有限，缺稳定 B2B 来源","d":"品牌方、渠道商、采购商等精准客户开发依赖现有资源和零散机会，没有持续获客通道。"},{"t":"OEM/ODM 订单零散，难成气候","d":"研发、开模、定制能力俱全，但缺少标准化的获客、需求承接与订单转化体系。"},{"t":"产品多，但产品—客户—渠道不匹配","d":"加热眼罩、护膝、马甲、披毯、玩偶对应不同场景与客群，重点产品、重点行业、重点渠道待明确。"}]'::jsonb,
 '[{"t":"产品×场景×渠道／匹配矩阵","d":"梳理产品线，锁定重点产品与重点行业"},{"t":"目标客户画像／获客通道搭建","d":"建立 B2B 精准客户持续获取的稳定通道"},{"t":"询盘承接／转化 SOP","d":"OEM/ODM 需求承接与订单转化的标准流程"},{"t":"AI 获客工具／部署陪跑","d":"工具上线、指标复盘，陪跑到达产"}]'::jsonb,
 '项目价值',
 '从「等订单」到「有体系地拿订单」：清晰的重点产品、重点行业与重点渠道，加一套可复制的 OEM/ODM 转化流程。',
 6000, true, now() - interval '2 days', now() - interval '2 days')
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published,
   first_pub_at, last_pub_at)
values
('p003', 'strategy', '连锁餐饮 / 消费服务', '多品牌扩张', '2026.11-2027.05', '询单中',
 '区域连锁餐饮集团：新品牌战略定位与扩张路径设计',
 '为一家多品牌区域连锁餐饮集团，理清「下一个五年靠什么增长」的战略命题',
 '[{"k":"企业性质","v":"连锁餐饮管理企业"},{"k":"现有业务","v":"成熟西餐连锁品牌运营"},{"k":"区域布局","v":"区域深耕，辐射周边市场"},{"k":"核心诉求","v":"新品牌孵化与集团化扩张"}]'::jsonb,
 '[{"t":"增长依赖单品牌，第二曲线模糊","d":"主品牌进入成熟期，新品牌方向多次试水未形成清晰定位，资源投放心里有底、手上没谱。"},{"t":"单店盈利模型未跑通就谈复制","d":"门店模型、人效与坪效标准不统一，扩张节奏缺乏数据支撑。"},{"t":"集团管控跟不上多品牌节奏","d":"总部与门店权责不清，供应链与人才供给难以支撑多线扩张。"}]'::jsonb,
 '[{"t":"战略诊断／增长意图澄清","d":"盘点资源禀赋，聚焦战略方向"},{"t":"新品牌定位／单店模型验证","d":"锁定细分赛道，打磨可复制盈利模型"},{"t":"扩张路径／与节奏设计","d":"分阶段增长路径与资源投放组合"},{"t":"集团管控／落地陪跑","d":"总部—门店权责与人才供给体系搭好"}]'::jsonb,
 '项目价值',
 '一套「定位—模型—复制」的扩张操作系统：新品牌有据可依，扩张节奏有数可算，集团管控有人可用。',
 5000, true, now() - interval '3 days', now() - interval '3 days')
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published,
   first_pub_at, last_pub_at)
values
('p004', 'perf', '产业园区运营', '全国多园区', '2026.10-2026.12', '询单中',
 '产业园区运营服务商：全国园区全维度绩效管理体系设计',
 '为一家布局全国多个园区的运营服务商，把「招商转化、租金收缴、空置控制」装进一套考核体系',
 '[{"k":"企业性质","v":"产业园区运营服务商"},{"k":"业务规模","v":"全国多城市园区布局"},{"k":"核心业务","v":"园区开发运营 + 企业服务"},{"k":"核心诉求","v":"统一考核，激活招商"}]'::jsonb,
 '[{"t":"考核「走形式」，指标与业务脱节","d":"现有考核停留在出勤与主观评价，招商转化率、租金收缴率、空置率等关键结果未进入指标体系。"},{"t":"园区间差异大，一把尺子量不准","d":"不同园区处于入驻周期不同阶段，统一标准失真、分园标准难服众。"},{"t":"考核结果与激励脱钩","d":"干好干坏差别不大，招商骨干动力不足，目标达成缺少机制保障。"}]'::jsonb,
 '[{"t":"业务指标／体系梳理","d":"从园区经营结果倒推考核指标"},{"t":"分园差异化／指标设计","d":"按园区周期阶段定制权重与基线"},{"t":"考核激励／联动机制","d":"结果与奖金、晋升强挂钩"},{"t":"试运行／复盘校准","d":"小范围试点后全国推广"}]'::jsonb,
 '项目价值',
 '一套覆盖全国园区的绩效操作系统：关键指标进考核、考核结果进激励，招商目标达成有机制兜底。',
 4000, true, now() - interval '4 days', now() - interval '4 days')
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published,
   first_pub_at, last_pub_at)
values
('p005', 'org', '电商零售', '组织效能', '2026.12-2027.06', '询单中',
 '电商企业：业绩扩张期的组织架构重塑与人才梯队建设',
 '为一家处于规模跃升期的电商企业，解决「业务翻倍、组织没跟上」的扩张阵痛',
 '[{"k":"企业性质","v":"综合电商企业"},{"k":"业务规模","v":"多仓布局、全国发货"},{"k":"团队规模","v":"数百人，一线为主"},{"k":"核心诉求","v":"组织先于业务准备好"}]'::jsonb,
 '[{"t":"架构随业务长歪，权责含糊","d":"部门设置沿革多于设计，跨部门协作靠人情，关键流程无人端到端负责。"},{"t":"一线人才选拔培训不成体系","d":"业务扩张快于人才供给，新人合格率波动大，执行质量不稳定。"},{"t":"人效看不见、算不清","d":"缺少人效模型与数据看板，人力成本增长快于营收增长。"}]'::jsonb,
 '[{"t":"组织诊断／架构再设计","d":"按业务价值链重排部门与权责"},{"t":"岗位梳理／人效模型","d":"关键岗位再设计，建立人效基线"},{"t":"人才选拔／培训体系","d":"标准化选育用留，稳定一线质量"},{"t":"流程优化／数据看板","d":"流程提效上线，人效月度复盘"}]'::jsonb,
 '项目价值',
 '在不扩张人力成本的前提下托住业绩跃升：架构清晰、人效可算、一线执行质量稳定。',
 3000, true, now() - interval '5 days', now() - interval '5 days')
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published,
   first_pub_at, last_pub_at)
values
('p006', 'talent', '新能源材料', '人才体系', '2027.01-2027.06', '询单中',
 '新能源材料企业：关键岗位胜任力模型与人才画像体系搭建',
 '为一家快速扩张的新材料企业，把「招不准、育不出、留不住」的人才难题变成一套标准',
 '[{"k":"企业性质","v":"新能源电池材料企业"},{"k":"产业布局","v":"国内外多基地运营"},{"k":"发展阶段","v":"产能与技术双扩张期"},{"k":"核心诉求","v":"关键岗位选人有标准"}]'::jsonb,
 '[{"t":"关键岗位没有人才标准","d":"选人靠面试官个人经验，同一岗位不同面试官结论迥异，错招成本高。"},{"t":"招聘合格率不稳定","d":"到岗后表现与面试评估偏差大，试用期淘汰消耗团队精力。"},{"t":"梯队断层，晋升无路径","d":"骨干晋升靠资历排队，高潜人才看不到成长地图，流失风险积聚。"}]'::jsonb,
 '[{"t":"人才定位／标准共创","d":"与业务共定关键岗位人才标准"},{"t":"胜任力模型／人才画像","d":"能力项行为化，画像可评估"},{"t":"嵌入招聘／合格率验证","d":"画像落地招聘流程，跟踪合格率"},{"t":"发展路径／梯队地图","d":"晋升路径与培养计划成体系"}]'::jsonb,
 '项目价值',
 '让关键岗位「选人有尺、育人有梯、晋升有图」：招聘合格率可验证，高潜人才看得见未来。',
 2000, true, now() - interval '6 days', now() - interval '6 days')
on conflict (project_id) do nothing;

insert into public.projects
  (project_id, category, industry, tech_tag, period, status_text, title, subtitle,
   profile, challenges, steps, value_title, value_desc, sort, published,
   first_pub_at, last_pub_at)
values
('p007', 'training', '服饰零售', '销售铁军', '2026.10-2026.12', '询单中',
 '服饰集团销售分公司：「百万销冠」高绩效训练营',
 '为一家服饰集团区域分公司，把「靠个别高手出单」变成「人人有打法、店店有销冠」',
 '[{"k":"企业性质","v":"服饰集团区域分公司"},{"k":"团队构成","v":"多门店一线销售团队"},{"k":"业务特征","v":"线下成交为主、客单差异大"},{"k":"核心诉求","v":"销售业绩整体拉升"}]'::jsonb,
 '[{"t":"业绩靠高手，不靠体系","d":"少数销冠贡献大半业绩，打法沉淀不下来，人一走业绩就塌。"},{"t":"中间层能力断档","d":"大量一线销售停留在「等客上门」，缺乏主动成交与连单能力。"},{"t":"培训听过就忘，落不了地","d":"过往培训缺少实战演练与后续跟踪，行为改变几乎为零。"}]'::jsonb,
 '[{"t":"销冠打法／萃取建模","d":"把高手经验变成可教的打法库"},{"t":"实战训练营／分组对抗","d":"场景演练 + 通关考核，练到会为止"},{"t":"AI 陪练／日常固化","d":"智能体陪练嵌入日常，持续练兵"},{"t":"业绩追踪／复盘迭代","d":"训练期业绩对比复盘，打法迭代"}]'::jsonb,
 '项目价值',
 '销冠经验资产化、训练日常化：团队整体成交能力上台阶，业绩不再系于个别人。',
 1000, true, now() - interval '7 days', now() - interval '7 days')
on conflict (project_id) do nothing;

-- ---------- 9. 简历投递（前端「投递简历」→ 后台「查看简历」） ----------
-- 本节全部是「create if not exists / create or replace」，不做任何 update 或 delete，
-- 不会改动 admins / sessions / submissions / consultants / project_interest / projects
-- 里任何一条既有数据，可放心重复执行。

-- 9.1 简历主表：只存文字信息与文件元数据，文件正文按片存在 resume_parts
create table if not exists public.resumes (
  id         uuid primary key default gen_random_uuid(),
  project_id text not null,                       -- 投递到哪个项目（对应 projects.project_id）
  name       text not null,
  phone      text not null,
  email      text not null default '',
  intro      text not null default '',
  file_name  text not null default '',
  file_type  text not null default '',
  file_size  bigint not null default 0,
  parts      int not null default 0,
  complete   boolean not null default false,      -- 文件全部传完才置 true，列表只展示 true 的记录
  created_at timestamptz not null default now()
);

-- 同一项目下「姓名 + 手机号」唯一 → 重复投递由数据库直接拦下
create unique index if not exists resumes_uniq_idx
  on public.resumes (project_id, lower(btrim(name)), btrim(phone));
create index if not exists resumes_proj_idx    on public.resumes (project_id, created_at desc);
create index if not exists resumes_created_idx on public.resumes (created_at desc);

-- 9.2 文件分片：前端把文件切成小片存进来，避免单次请求过大，
--     下载时按 seq 顺序拼回原文件，文件内容不会被改动或损伤
create table if not exists public.resume_parts (
  resume_id uuid not null references public.resumes(id) on delete cascade,
  seq       int  not null,
  chunk     text not null,
  primary key (resume_id, seq)
);

-- 9.3 下载留痕：谁在什么时候下载过哪份简历（仅总管理员可查看）
create table if not exists public.resume_downloads (
  id         uuid primary key default gen_random_uuid(),
  resume_id  uuid not null references public.resumes(id) on delete cascade,
  admin_id   uuid,
  admin_name text not null default '',
  created_at timestamptz not null default now()
);
create index if not exists resume_dl_idx on public.resume_downloads (resume_id, created_at desc);

-- 9.4 RLS：三张表一律不建 policy → 匿名与登录用户都无法直接读写，
--     只能通过下面这些 security definer 函数访问
alter table public.resumes          enable row level security;
alter table public.resume_parts     enable row level security;
alter table public.resume_downloads enable row level security;

-- 9.5 投递第一步：建记录（返回 id 供后续分片上传）
create or replace function public.resume_submit(
  p_project_id text, p_name text, p_phone text,
  p_email text, p_intro text,
  p_file_name text, p_file_type text, p_file_size bigint
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_pid text; v_name text; v_phone text; v_row public.resumes;
begin
  v_pid   := btrim(coalesce(p_project_id, ''));
  v_name  := btrim(coalesce(p_name, ''));
  v_phone := btrim(coalesce(p_phone, ''));

  if v_pid = '' then
    return json_build_object('ok', false, 'error', '项目参数缺失，请刷新页面后重试');
  end if;
  if v_name = '' then
    return json_build_object('ok', false, 'error', '请填写姓名');
  end if;
  if v_phone !~ '^1[0-9]{10}$' then
    return json_build_object('ok', false, 'error', '请填写 11 位手机号');
  end if;
  if coalesce(p_file_size, 0) <= 0 then
    return json_build_object('ok', false, 'error', '请选择简历文件');
  end if;
  if coalesce(p_file_size, 0) > 20 * 1024 * 1024 then
    return json_build_object('ok', false, 'error', '文件过大，请上传 20MB 以内的简历');
  end if;
  if not exists (select 1 from public.projects where project_id = v_pid) then
    return json_build_object('ok', false, 'error', '项目不存在或已下线，请刷新页面后重试');
  end if;

  -- 同项目同姓名同手机号只能投一次
  if exists (select 1 from public.resumes
              where project_id = v_pid
                and lower(btrim(name)) = lower(v_name)
                and btrim(phone) = v_phone
                and complete = true) then
    return json_build_object('ok', false, 'duplicate', true,
                             'error', '你已投递过该项目的简历，无需重复提交');
  end if;

  -- 清掉同人上一次没传完的残留（只针对未完成的临时记录，不影响任何已完成简历）
  delete from public.resumes
   where project_id = v_pid and lower(btrim(name)) = lower(v_name)
     and btrim(phone) = v_phone and complete = false;

  insert into public.resumes (project_id, name, phone, email, intro, file_name, file_type, file_size)
  values (v_pid, v_name, v_phone, coalesce(p_email, ''), coalesce(p_intro, ''),
          coalesce(p_file_name, ''), coalesce(p_file_type, ''), p_file_size)
  returning * into v_row;

  return json_build_object('ok', true, 'id', v_row.id);
exception
  when unique_violation then
    return json_build_object('ok', false, 'duplicate', true,
                             'error', '你已投递过该项目的简历，无需重复提交');
end;
$$;

-- 9.6 投递第二步：逐片上传文件（每片约 700KB 明文，base64 后仍远小于限制）
create or replace function public.resume_part_add(p_id uuid, p_seq int, p_chunk text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_pending boolean;
begin
  if p_id is null or p_seq is null or p_seq < 0 then
    return json_build_object('ok', false, 'error', '参数错误');
  end if;
  if length(coalesce(p_chunk, '')) > 1500000 then
    return json_build_object('ok', false, 'error', '单个分片过大');
  end if;
  select true into v_pending from public.resumes where id = p_id and complete = false;
  if v_pending is null then
    return json_build_object('ok', false, 'error', '投递记录不存在或已完成');
  end if;
  insert into public.resume_parts (resume_id, seq, chunk)
  values (p_id, p_seq, p_chunk)
  on conflict (resume_id, seq) do update set chunk = excluded.chunk;
  return json_build_object('ok', true);
end;
$$;

-- 9.7 投递第三步：全部片传完，标记完成（此前的记录对后台不可见）
create or replace function public.resume_submit_done(p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_n int;
begin
  if p_id is null then
    return json_build_object('ok', false, 'error', '参数错误');
  end if;
  select count(*) into v_n from public.resume_parts where resume_id = p_id;
  if v_n = 0 then
    return json_build_object('ok', false, 'error', '文件尚未上传完成');
  end if;
  update public.resumes set complete = true, parts = v_n where id = p_id and complete = false;
  if not found then
    return json_build_object('ok', false, 'error', '投递记录不存在或已完成');
  end if;
  return json_build_object('ok', true, 'parts', v_n);
end;
$$;

-- 9.8 投递失败清理：删掉未完成的临时记录（已完成的简历不受影响）
create or replace function public.resume_abort(p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  if p_id is null then
    return json_build_object('ok', true);
  end if;
  delete from public.resumes where id = p_id and complete = false;
  return json_build_object('ok', true);
end;
$$;

-- 9.9 后台：每个项目的简历份数（用于「查看简历」按钮上的数字）
create or replace function public.resume_counts(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  return json_build_object('ok', true, 'counts', (
    select coalesce(json_object_agg(t.project_id, t.n), '{}'::json)
      from (select project_id, count(*)::int as n
              from public.resumes where complete = true
             group by project_id) t
  ));
end;
$$;

-- 9.10 后台：某个项目的简历列表（p_project_id 为空则返回全部）
--      下载留痕只有总管理员能拿到，普通管理员拿到的一律是空数组
create or replace function public.resume_list(p_token text, p_project_id text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_super boolean;
  v_pid   text;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  v_super := (v_admin.role = 'super');
  v_pid   := btrim(coalesce(p_project_id, ''));
  return json_build_object('ok', true, 'super', v_super, 'resumes', (
    select coalesce(json_agg(json_build_object(
      'id', r.id, 'project_id', r.project_id,
      'name', r.name, 'phone', r.phone, 'email', r.email, 'intro', r.intro,
      'file_name', r.file_name, 'file_type', r.file_type, 'file_size', r.file_size,
      'created_at', r.created_at,
      'dls', case when v_super then (
        select coalesce(json_agg(json_build_object('who', d.admin_name, 'at', d.created_at)
                                 order by d.created_at), '[]'::json)
          from public.resume_downloads d where d.resume_id = r.id
      ) else '[]'::json end
    ) order by r.created_at desc), '[]'::json)
    from public.resumes r
    where r.complete = true and (v_pid = '' or r.project_id = v_pid)
  ));
end;
$$;

-- 9.11 后台：取简历文件内容（base64），用于在线预览与下载
create or replace function public.resume_file(p_token text, p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_row   public.resumes;
  v_data  text;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  select * into v_row from public.resumes where id = p_id;
  if v_row.id is null then
    return json_build_object('ok', false, 'error', '简历不存在或已删除');
  end if;
  select coalesce(string_agg(chunk, '' order by seq), '') into v_data
    from public.resume_parts where resume_id = p_id;
  if coalesce(v_data, '') = '' then
    return json_build_object('ok', false, 'error', '文件内容缺失');
  end if;
  return json_build_object('ok', true,
    'file_name', v_row.file_name, 'file_type', v_row.file_type,
    'file_size', v_row.file_size, 'data', v_data);
end;
$$;

-- 9.12 后台：导出/下载简历时写一条留痕，并告诉前端「此前是否已被下载过」
create or replace function public.resume_download_mark(p_token text, p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin  public.admins;
  v_before int;
  v_who    text;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if not exists (select 1 from public.resumes where id = p_id and complete = true) then
    return json_build_object('ok', false, 'error', '简历不存在或已删除');
  end if;
  select count(*) into v_before from public.resume_downloads where resume_id = p_id;
  v_who := coalesce(nullif(btrim(v_admin.name), ''), '管理员')
           || case when v_admin.role = 'super' then '（总管理员）' else '' end;
  insert into public.resume_downloads (resume_id, admin_id, admin_name)
  values (p_id, v_admin.id, v_who);
  return json_build_object('ok', true, 'first', v_before = 0, 'times', v_before + 1, 'who', v_who);
end;
$$;

-- 9.13 后台：删除简历（仅总管理员；分片与留痕随外键级联删除）
create or replace function public.resume_delete(p_token text, p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  if v_admin.role <> 'super' then
    return json_build_object('ok', false, 'error', '仅总管理员可删除简历');
  end if;
  delete from public.resumes where id = p_id;
  if not found then
    return json_build_object('ok', false, 'error', '记录不存在或已删除');
  end if;
  return json_build_object('ok', true);
end;
$$;

-- 9.14 调用权限：投递三个函数匿名可用，后台四个函数需要 token
grant execute on function
  public.resume_submit(text, text, text, text, text, text, text, bigint),
  public.resume_part_add(uuid, int, text),
  public.resume_submit_done(uuid),
  public.resume_abort(uuid),
  public.resume_counts(text),
  public.resume_list(text, text),
  public.resume_file(text, uuid),
  public.resume_download_mark(text, uuid),
  public.resume_delete(text, uuid)
to anon, authenticated;

-- ---------- 10. 管理员密码记录与重置（账号 + 当前密码同步到总管理员后台） ----------

-- 10.0 密码明文记录表：添加 / 自改 / 重置密码时同步写入一份明文，供总管理员在后台查看。
--      不建任何 policy，只能通过下方安全函数读写；admin_list 仅总管理员可调用。
create table if not exists public.admin_password_notes (
  admin_id       uuid primary key references public.admins(id) on delete cascade,
  password_plain text not null,
  updated_at     timestamptz not null default now()
);
alter table public.admin_password_notes enable row level security;

-- 10.1 重置密码：仅 super；重置后该管理员所有会话立即失效，须用新密码重新登录
create or replace function public.admin_reset_password(p_token text, p_admin_id uuid, p_new_password text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin  public.admins;
  v_target public.admins;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if v_admin.role <> 'super' then
    return json_build_object('ok', false, 'error', '仅总管理员可操作');
  end if;
  if p_new_password is null or length(p_new_password) < 6 then
    return json_build_object('ok', false, 'error', '新密码至少 6 位');
  end if;
  select * into v_target from public.admins where id = p_admin_id limit 1;
  if v_target.id is null then
    return json_build_object('ok', false, 'error', '管理员不存在或已被删除');
  end if;
  update public.admins set password_hash = crypt(p_new_password, gen_salt('bf'))
  where id = p_admin_id;
  delete from public.sessions where admin_id = p_admin_id;
  insert into public.admin_password_notes (admin_id, password_plain)
  values (p_admin_id, p_new_password)
  on conflict (admin_id) do update set password_plain = excluded.password_plain, updated_at = now();
  return json_build_object('ok', true, 'phone', v_target.phone, 'name', v_target.name);
end;
$$;

-- 10.2 与第 4 节完全一致的最新版函数（在这里重建一次，保证只执行增量段时也生效）
create or replace function public.admin_create(p_token text, p_phone text, p_password text, p_name text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_admin public.admins; v_new uuid;
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
  values (p_phone, crypt(p_password, gen_salt('bf')), nullif(trim(p_name), ''), 'admin')
  returning id into v_new;
  insert into public.admin_password_notes (admin_id, password_plain)
  values (v_new, p_password)
  on conflict (admin_id) do update set password_plain = excluded.password_plain, updated_at = now();
  return json_build_object('ok', true);
end;
$$;

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
  insert into public.admin_password_notes (admin_id, password_plain)
  values (v_admin.id, p_new)
  on conflict (admin_id) do update set password_plain = excluded.password_plain, updated_at = now();
  return json_build_object('ok', true);
end;
$$;

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
      'role', a.role, 'password', n.password_plain,
      'created_at', a.created_at) order by a.created_at), '[]'::json)
    from public.admins a
    left join public.admin_password_notes n on n.admin_id = a.id
    where a.role <> 'consultant'          -- 咨询师账号不在「管理员管理」里展示
  ));
end;
$$;

-- 10.3 调用权限：与其它后台函数一致
grant execute on function public.admin_reset_password(text, uuid, text)
to anon, authenticated;
grant execute on function public.admin_create(text, text, text, text)
to anon, authenticated;
grant execute on function public.admin_change_password(text, text, text)
to anon, authenticated;
grant execute on function public.admin_list(text)
to anon, authenticated;

-- ---------- 11. 咨询师账号体系（同意申请 → 咨询师登录自己的后台） ----------
--
-- 本节只增加结构与新函数，不改动任何已有数据：
--   · admins.role 增加 consultant（咨询师登录账号，与管理员共用一套登录）
--   · consultants 增加 项目案例 / 观点 / 申请资料 / 绑定的登录账号
--   · project_interest 增加 admin_id（咨询师点「感兴趣」时记名）
--   · 新增同意申请、读取与保存自己的资料、我的感兴趣、我的投递、点赞等函数
-- 全部 create ... if not exists / create or replace，可重复执行。

-- 11.0 submissions 的处理字段（旧版本升级脚本里已有，这里补一次，
--      保证只执行本次增量时也不会缺列）
alter table public.submissions add column if not exists status text not null default 'pending'
  check (status in ('pending','handled'));
alter table public.submissions add column if not exists handler_phone text;
alter table public.submissions add column if not exists handler_name text;
alter table public.submissions add column if not exists handled_at timestamptz;
alter table public.submissions add column if not exists notes text;
create index if not exists submissions_status_idx on public.submissions (status);

-- 11.1 admins.role 放宽：新增 consultant 角色
do $$
declare c record;
begin
  for c in
    select conname from pg_constraint
    where conrelid = 'public.admins'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) ilike '%role%'
  loop
    execute format('alter table public.admins drop constraint %I', c.conname);
  end loop;
end $$;
alter table public.admins add constraint admins_role_check
  check (role in ('super','admin','consultant'));

-- 11.2 consultants 扩展
--   cases   = 项目案例 [{"t":"标题","d":"描述"}, ...]
--   views   = 专业观点 [{"t":"标题","d":"描述"}, ...]
--   profile = 咨询师申请时填写的原始资料（个人中心里可修改后同步）
--   admin_id = 绑定的登录账号（为空表示还没开通账号）
alter table public.consultants add column if not exists cases    jsonb not null default '[]'::jsonb;
alter table public.consultants add column if not exists views    jsonb not null default '[]'::jsonb;
alter table public.consultants add column if not exists profile  jsonb not null default '{}'::jsonb;
alter table public.consultants add column if not exists admin_id uuid;
create unique index if not exists consultants_admin_idx
  on public.consultants (admin_id) where admin_id is not null;

-- 11.3 project_interest 增加记名字段
alter table public.project_interest add column if not exists admin_id uuid;
create unique index if not exists project_interest_admin_idx
  on public.project_interest (project_id, admin_id) where admin_id is not null;

-- 11.4 同意咨询师申请：开通登录账号（默认密码 123456）+ 建立/复用介绍卡片
create or replace function public.consultant_apply_approve(p_token text, p_submission_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me     public.admins;
  v_sub    public.submissions;
  v_target public.admins;
  v_name   text;
  v_phone  text;
  v_title  text;
  v_bio    text;
  v_new    uuid;
  v_cid    uuid;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if v_me.role not in ('super','admin') then
    return json_build_object('ok', false, 'error', '无权限操作');
  end if;

  select * into v_sub from public.submissions where id = p_submission_id limit 1;
  if v_sub.id is null then
    return json_build_object('ok', false, 'error', '记录不存在');
  end if;
  if v_sub.type <> 'apply' then
    return json_build_object('ok', false, 'error', '只有咨询师申请可以「同意」');
  end if;

  v_name  := btrim(coalesce(v_sub.data->>'name', ''));
  v_phone := btrim(coalesce(v_sub.data->>'phone', ''));
  if v_name = '' then
    return json_build_object('ok', false, 'error', '该申请没有姓名，无法开通账号');
  end if;
  if v_phone !~ '^1\d{10}$' then
    return json_build_object('ok', false, 'error', '该申请没有有效手机号，无法开通账号');
  end if;

  -- 头衔取「擅长的领域」，没有则用「擅长的行业」
  v_title := nullif(btrim(coalesce(v_sub.data->>'field', '')), '');
  if v_title is null then v_title := nullif(btrim(coalesce(v_sub.data->>'industry', '')), ''); end if;
  if v_title is null then v_title := '项目咨询师'; end if;

  -- 简介取「咨询行业经历」，没有则用公司名
  v_bio := nullif(btrim(coalesce(v_sub.data->>'experience', '')), '');
  if v_bio is null then v_bio := nullif(btrim(coalesce(v_sub.data->>'company', '')), ''); end if;
  if v_bio is null then v_bio := ''; end if;

  select * into v_target from public.admins where phone = v_phone limit 1;
  if v_target.id is not null then
    if v_target.role <> 'consultant' then
      return json_build_object('ok', false,
        'error', '该手机号已是管理员账号，不能同时作为咨询师登录');
    end if;
    v_new := v_target.id;
  else
    insert into public.admins (phone, password_hash, name, role)
    values (v_phone, crypt('123456', gen_salt('bf')), v_name, 'consultant')
    returning id into v_new;
    insert into public.admin_password_notes (admin_id, password_plain)
    values (v_new, '123456')
    on conflict (admin_id) do update
      set password_plain = excluded.password_plain, updated_at = now();
  end if;

  select id into v_cid from public.consultants where admin_id = v_new limit 1;
  if v_cid is null then
    insert into public.consultants (name, title, bio, image, profile, admin_id)
    values (v_name, v_title, v_bio, '', coalesce(v_sub.data, '{}'::jsonb), v_new)
    returning id into v_cid;
  else
    -- 已有卡片：只补空的申请资料，不覆盖他本人已经改过的内容
    update public.consultants
       set profile = coalesce(v_sub.data, '{}'::jsonb)
     where id = v_cid
       and (profile is null or profile = '{}'::jsonb);
  end if;

  update public.submissions
     set status        = 'handled',
         handler_phone = v_me.phone,
         handler_name  = v_me.name,
         handled_at    = now()
   where id = p_submission_id;

  return json_build_object('ok', true, 'consultant_id', v_cid,
    'phone', v_phone, 'name', v_name, 'password', '123456');
end;
$$;

-- 11.5 咨询师：读取自己的账号与介绍卡片
create or replace function public.consultant_me(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me  public.admins;
  v_row public.consultants;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  select * into v_row from public.consultants where admin_id = v_me.id limit 1;
  return json_build_object('ok', true,
    'phone', v_me.phone,
    'name',  coalesce(nullif(v_me.name, ''), v_row.name),
    'consultant', case when v_row.id is null then null else json_build_object(
      'id',      v_row.id,
      'name',    v_row.name,
      'title',   v_row.title,
      'bio',     v_row.bio,
      'image',   v_row.image,
      'cases',   coalesce(v_row.cases, '[]'::jsonb),
      'views',   coalesce(v_row.views, '[]'::jsonb),
      'profile', coalesce(v_row.profile, '{}'::jsonb)
    ) end);
end;
$$;

-- 11.6 咨询师：保存自己的介绍（与后台「咨询师管理」格式一致，保存后官网立即更新）
create or replace function public.consultant_save_self(
  p_token text,
  p_name  text,
  p_title text,
  p_bio   text,
  p_image text,
  p_cases jsonb,
  p_views jsonb
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me  public.admins;
  v_row public.consultants;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  p_name  := btrim(coalesce(p_name, ''));
  p_title := btrim(coalesce(p_title, ''));
  if p_name = '' or p_title = '' then
    return json_build_object('ok', false, 'error', '姓名与头衔为必填');
  end if;

  select * into v_row from public.consultants where admin_id = v_me.id limit 1;
  if v_row.id is null then
    insert into public.consultants (name, title, bio, image, cases, views, admin_id)
    values (p_name, p_title, coalesce(p_bio, ''), coalesce(p_image, ''),
            coalesce(p_cases, '[]'::jsonb), coalesce(p_views, '[]'::jsonb), v_me.id)
    returning * into v_row;
  else
    update public.consultants set
      name  = p_name,
      title = p_title,
      bio   = coalesce(p_bio, ''),
      image = case when coalesce(p_image, '') = '' then image else p_image end,
      cases = coalesce(p_cases, cases),
      views = coalesce(p_views, views)
    where id = v_row.id
    returning * into v_row;
  end if;

  update public.admins set name = p_name where id = v_me.id;
  return json_build_object('ok', true, 'id', v_row.id);
end;
$$;

-- 11.7 咨询师：我点过「感兴趣」的项目
create or replace function public.consultant_my_interests(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me public.admins;
  v_js json;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  select coalesce(json_agg(json_build_object(
      'project_id', i.project_id,
      'title',      coalesce(p.title, i.project_id),
      'subtitle',   coalesce(p.subtitle, ''),
      'category',   coalesce(p.category, ''),
      'industry',   coalesce(p.industry, ''),
      'at',         i.created_at) order by i.created_at desc), '[]'::json)
    into v_js
    from public.project_interest i
    left join public.projects p on p.project_id = i.project_id
   where i.admin_id = v_me.id;
  return json_build_object('ok', true, 'projects', v_js);
end;
$$;

-- 11.8 咨询师：我投递过简历的项目（按申请手机号匹配）
create or replace function public.consultant_my_resumes(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me public.admins;
  v_js json;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  begin
    select coalesce(json_agg(x order by x->>'at' desc), '[]'::json) into v_js from (
      select json_build_object(
        'project_id', r.project_id,
        'title',      coalesce(p.title, r.project_id),
        'subtitle',   coalesce(p.subtitle, ''),
        'category',   coalesce(p.category, ''),
        'file_name',  r.file_name,
        'at',         r.created_at) as x
        from public.resumes r
        left join public.projects p on p.project_id = r.project_id
       where btrim(r.phone) = btrim(v_me.phone)
    ) t;
  exception when undefined_table then
    v_js := '[]'::json;      -- 简历功能还没建表时不报错，返回空
  end;
  return json_build_object('ok', true, 'projects', v_js);
end;
$$;

-- 11.9 咨询师：在自己后台点 / 取消「感兴趣」
create or replace function public.consultant_interest_toggle(p_token text, p_project_id text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me  public.admins;
  v_on  boolean;
  v_cnt int;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if p_project_id is null or btrim(p_project_id) = '' then
    return json_build_object('ok', false, 'error', '缺少项目编号');
  end if;
  if exists (select 1 from public.project_interest
              where project_id = p_project_id and admin_id = v_me.id) then
    delete from public.project_interest
     where project_id = p_project_id and admin_id = v_me.id;
    v_on := false;
  else
    insert into public.project_interest (project_id, ip_hash, admin_id)
    values (p_project_id,
            encode(digest('cc_consultant:' || v_me.id::text, 'sha256'), 'hex'),
            v_me.id)
    on conflict (project_id, ip_hash) do update
      set admin_id = coalesce(public.project_interest.admin_id, excluded.admin_id);
    v_on := true;
  end if;
  select count(*) into v_cnt from public.project_interest where project_id = p_project_id;
  return json_build_object('ok', true, 'on', v_on, 'count', v_cnt);
end;
$$;

-- 11.10 官网点赞（带咨询师登录态时把这票记到该咨询师名下，否则等同匿名投票）
create or replace function public.project_interest_vote_as(p_project_id text, p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me   public.admins;
  v_raw  text;
  v_ip   text;
  v_hash text;
  v_cnt  int;
begin
  if p_project_id is null or btrim(p_project_id) = '' then
    return json_build_object('ok', false, 'error', '缺少项目编号');
  end if;
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return public.project_interest_vote(p_project_id);
  end if;
  -- 这位咨询师已经点过：不重复计数
  if exists (select 1 from public.project_interest
              where project_id = p_project_id and admin_id = v_me.id) then
    select count(*) into v_cnt from public.project_interest where project_id = p_project_id;
    return json_build_object('ok', true, 'count', v_cnt, 'first', false, 'named', true);
  end if;
  v_raw := coalesce(current_setting('request.headers', true)::json->>'x-forwarded-for', '');
  v_ip  := btrim(split_part(v_raw, ',', 1));
  if v_ip is null or v_ip = '' then v_ip := 'unknown'; end if;
  v_hash := encode(digest('cc_salt_2026:' || v_ip, 'sha256'), 'hex');
  insert into public.project_interest (project_id, ip_hash, admin_id)
  values (p_project_id, v_hash, v_me.id)
  on conflict (project_id, ip_hash) do update
    set admin_id = coalesce(public.project_interest.admin_id, excluded.admin_id);
  select count(*) into v_cnt from public.project_interest where project_id = p_project_id;
  return json_build_object('ok', true, 'count', v_cnt, 'first', true, 'named', true);
end;
$$;

-- 11.11 咨询师：保存个人信息（申请时填写的资料，可修改）
create or replace function public.consultant_profile_save(p_token text, p_profile jsonb)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me  public.admins;
  v_row public.consultants;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if p_profile is null then
    return json_build_object('ok', false, 'error', '没有需要保存的内容');
  end if;
  select * into v_row from public.consultants where admin_id = v_me.id limit 1;
  if v_row.id is null then
    return json_build_object('ok', false, 'error', '介绍卡片不存在，请先保存咨询师介绍');
  end if;
  update public.consultants
     set profile = p_profile
   where id = v_row.id;
  if coalesce(btrim(p_profile->>'name'), '') <> '' then
    update public.admins set name = btrim(p_profile->>'name') where id = v_me.id;
  end if;
  return json_build_object('ok', true);
end;
$$;

-- 11.12 调用权限
grant execute on function public.consultant_apply_approve(text, uuid)      to anon, authenticated;
grant execute on function public.consultant_me(text)                       to anon, authenticated;
grant execute on function public.consultant_save_self(text, text, text, text, text, jsonb, jsonb)
  to anon, authenticated;
grant execute on function public.consultant_my_interests(text)             to anon, authenticated;
grant execute on function public.consultant_my_resumes(text)               to anon, authenticated;
grant execute on function public.consultant_interest_toggle(text, text)    to anon, authenticated;
grant execute on function public.project_interest_vote_as(text, text)      to anon, authenticated;
grant execute on function public.consultant_profile_save(text, jsonb)      to anon, authenticated;

-- ---------- 12. 咨询师后台数据隔离（各账号各管各的数据，互不串号） ----------
-- 本节全部是 create or replace / revoke / grant，只有权限与函数逻辑，
-- 不新增、不修改、不删除任何一条已有数据，可重复执行。

-- 12.1 介绍卡片：公开只读「展示字段」，申请资料（profile）不再对外可读
--      卡片里 profile 存着申请时填的手机号、期望薪资等个人信息，
--      原来整表对匿名访客可读（policy using(true)），等于所有人的资料都公开。
--      这里收回整表读权限，只放开首页 / 详情页真正要展示的那几列。
revoke select on public.consultants from anon, authenticated;
grant select (id, name, title, bio, image, cases, views, sort, created_at, admin_id)
  on public.consultants to anon, authenticated;

-- 12.2 官网点赞：咨询师登录态下的这一票按「咨询师」记账，不再借用 IP 哈希
--      原来用 IP 哈希有两个串号问题：
--      ① 同办公室同一个出口 IP，咨询师 A 的票会被后来点的人「顶」掉或误记；
--      ② 匿名访客的票与咨询师的票会互相同一条记录冲突。
--      改成每个咨询师一个固定哈希（cc_consultant:<账号 id>）后互不干扰。
create or replace function public.project_interest_vote_as(p_project_id text, p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me   public.admins;
  v_hash text;
  v_cnt  int;
begin
  if p_project_id is null or btrim(p_project_id) = '' then
    return json_build_object('ok', false, 'error', '缺少项目编号');
  end if;
  v_me := admin_from_token(p_token);
  -- 没有有效咨询师登录态：等同普通匿名投票（按 IP 去重）
  if v_me.id is null or v_me.role <> 'consultant' then
    return public.project_interest_vote(p_project_id);
  end if;
  v_hash := encode(digest('cc_consultant:' || v_me.id::text, 'sha256'), 'hex');
  -- 这位咨询师已经点过：不重复计数
  if exists (select 1 from public.project_interest
              where project_id = p_project_id and admin_id = v_me.id) then
    select count(*) into v_cnt from public.project_interest where project_id = p_project_id;
    return json_build_object('ok', true, 'count', v_cnt, 'first', false, 'named', true);
  end if;
  insert into public.project_interest (project_id, ip_hash, admin_id)
  values (p_project_id, v_hash, v_me.id)
  on conflict do nothing;
  select count(*) into v_cnt from public.project_interest where project_id = p_project_id;
  return json_build_object('ok', true, 'count', v_cnt, 'first', true, 'named', true);
end;
$$;

-- 12.3 咨询师后台点 / 取消「感兴趣」：目标永远是自己名下那一条
create or replace function public.consultant_interest_toggle(p_token text, p_project_id text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me   public.admins;
  v_on   boolean;
  v_hash text;
  v_cnt  int;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if p_project_id is null or btrim(p_project_id) = '' then
    return json_build_object('ok', false, 'error', '缺少项目编号');
  end if;
  v_hash := encode(digest('cc_consultant:' || v_me.id::text, 'sha256'), 'hex');
  if exists (select 1 from public.project_interest
              where project_id = p_project_id and admin_id = v_me.id) then
    -- 只删自己名下的那一条（连同本账号可能残留的同哈希行）
    delete from public.project_interest
     where project_id = p_project_id
       and (admin_id = v_me.id or ip_hash = v_hash);
    v_on := false;
  else
    insert into public.project_interest (project_id, ip_hash, admin_id)
    values (p_project_id, v_hash, v_me.id)
    on conflict do nothing;
    v_on := true;
  end if;
  select count(*) into v_cnt from public.project_interest where project_id = p_project_id;
  return json_build_object('ok', true, 'on', v_on, 'count', v_cnt);
end;
$$;

-- 12.4 咨询师保存自己的介绍卡片：
--      ① 只认「本账号名下的卡片」，绝不碰别人的卡片；
--      ② 若后台先手工建过一张同名的空白卡片（还没绑定账号），直接认领，
--         避免首页出现两张同名卡片。
create or replace function public.consultant_save_self(
  p_token text,
  p_name  text,
  p_title text,
  p_bio   text,
  p_image text,
  p_cases jsonb,
  p_views jsonb
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me  public.admins;
  v_row public.consultants;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  p_name  := btrim(coalesce(p_name, ''));
  p_title := btrim(coalesce(p_title, ''));
  if p_name = '' or p_title = '' then
    return json_build_object('ok', false, 'error', '姓名与头衔为必填');
  end if;

  select * into v_row from public.consultants where admin_id = v_me.id limit 1;

  if v_row.id is null then
    -- 认领后台手工建的同名空白卡片（未绑定账号、无个人资料）
    select * into v_row from public.consultants
     where admin_id is null
       and btrim(name) = p_name
       and (profile is null or profile = '{}'::jsonb)
     order by created_at asc limit 1;
    if v_row.id is not null then
      update public.consultants set admin_id = v_me.id where id = v_row.id;
    end if;
  end if;

  if v_row.id is null then
    insert into public.consultants (name, title, bio, image, cases, views, admin_id)
    values (p_name, p_title, coalesce(p_bio, ''), coalesce(p_image, ''),
            coalesce(p_cases, '[]'::jsonb), coalesce(p_views, '[]'::jsonb), v_me.id)
    returning * into v_row;
  else
    update public.consultants set
      name  = p_name,
      title = p_title,
      bio   = coalesce(p_bio, ''),
      image = case when coalesce(p_image, '') = '' then image else p_image end,
      cases = coalesce(p_cases, cases),
      views = coalesce(p_views, views)
    where id = v_row.id          -- 只改自己这一条
    returning * into v_row;
  end if;

  update public.admins set name = p_name where id = v_me.id;
  return json_build_object('ok', true, 'id', v_row.id);
end;
$$;

-- 12.5 咨询师保存个人信息：
--      手机号是登录账号，也是「投递项目」的匹配依据，这里强制等于账号手机号，
--      避免改了手机号以后自己的投递记录凭空消失（看着像数据被清）。
create or replace function public.consultant_profile_save(p_token text, p_profile jsonb)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me  public.admins;
  v_row public.consultants;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if p_profile is null or jsonb_typeof(p_profile) <> 'object' then
    return json_build_object('ok', false, 'error', '没有需要保存的内容');
  end if;

  p_profile := jsonb_set(p_profile, '{phone}', to_jsonb(v_me.phone));

  select * into v_row from public.consultants where admin_id = v_me.id limit 1;
  if v_row.id is null then
    select * into v_row from public.consultants
     where admin_id is null
       and btrim(name) = btrim(coalesce(p_profile->>'name', ''))
       and btrim(coalesce(p_profile->>'name', '')) <> ''
       and (profile is null or profile = '{}'::jsonb)
     order by created_at asc limit 1;
    if v_row.id is not null then
      update public.consultants set admin_id = v_me.id where id = v_row.id;
    end if;
  end if;
  if v_row.id is null then
    return json_build_object('ok', false, 'error', '介绍卡片还没有建立，请先在「咨询师介绍」里保存一次');
  end if;

  update public.consultants set profile = p_profile where id = v_row.id;

  if coalesce(btrim(p_profile->>'name'), '') <> '' then
    update public.admins set name = btrim(p_profile->>'name') where id = v_me.id;
  end if;
  return json_build_object('ok', true);
end;
$$;

-- 12.6 调用权限（与前面各节一致）
grant execute on function public.project_interest_vote_as(text, text)      to anon, authenticated;
grant execute on function public.consultant_interest_toggle(text, text)    to anon, authenticated;
grant execute on function public.consultant_save_self(text, text, text, text, text, jsonb, jsonb)
  to anon, authenticated;
grant execute on function public.consultant_profile_save(text, jsonb)      to anon, authenticated;

-- 让 PostgREST 立刻认识这些新函数（避免刚执行完调用报「找不到函数」）
notify pgrst, 'reload schema';

-- ---------- 13. 简历投递支持多文件（Word/PDF 与图片可任选其一，也可一起上传） ----------

-- 13.0 文件清单列：每项形如 {"name":..,"type":..,"size":..,"parts":..}，按上传顺序排列。
--      老记录此列为空数组，读写都会自动回退到 file_name / file_type / file_size，已有数据完全不受影响。
alter table public.resumes add column if not exists files jsonb not null default '[]'::jsonb;

-- 13.1 投递第一步（重建）：新增 p_files 参数（最多 2 份）。
--      file_name / file_type / file_size 仍然写第一份文件，后台列表摘要与「简历文件」列照旧可用。
create or replace function public.resume_submit(
  p_project_id text, p_name text, p_phone text,
  p_email text, p_intro text,
  p_file_name text, p_file_type text, p_file_size bigint,
  p_files jsonb default '[]'::jsonb
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_pid   text;
  v_name  text;
  v_phone text;
  v_row   public.resumes;
  v_files jsonb;
  v_n     int;
  v_total bigint;
  v_first jsonb;
begin
  v_pid   := btrim(coalesce(p_project_id, ''));
  v_name  := btrim(coalesce(p_name, ''));
  v_phone := btrim(coalesce(p_phone, ''));

  if v_pid = '' then
    return json_build_object('ok', false, 'error', '项目参数缺失，请刷新页面后重试');
  end if;
  if v_name = '' then
    return json_build_object('ok', false, 'error', '请填写姓名');
  end if;
  if v_phone !~ '^1[0-9]{10}$' then
    return json_build_object('ok', false, 'error', '请填写 11 位手机号');
  end if;
  if not exists (select 1 from public.projects where project_id = v_pid) then
    return json_build_object('ok', false, 'error', '项目不存在或已下线，请刷新页面后重试');
  end if;

  -- 只传了旧字段（老页面缓存）时，合成一份文件，保持完全兼容
  v_files := coalesce(p_files, '[]'::jsonb);
  if jsonb_typeof(v_files) <> 'array' or jsonb_array_length(v_files) = 0 then
    v_files := jsonb_build_array(jsonb_build_object(
      'name', coalesce(p_file_name, ''),
      'type', coalesce(p_file_type, ''),
      'size', coalesce(p_file_size, 0)
    ));
  end if;

  -- 规整每一份文件，并按「600KB 一片」算出分片数（与前端分片大小一致）
  select jsonb_agg(jsonb_build_object(
           'name',  coalesce(nullif(btrim(x->>'name'), ''), '简历'),
           'type',  coalesce(x->>'type', ''),
           'size',  coalesce((x->>'size')::bigint, 0),
           'parts', greatest(1, ceil(coalesce((x->>'size')::bigint, 0)::numeric / 614400)::int)
         ) order by ord)
    into v_files
    from jsonb_array_elements(v_files) with ordinality as t(x, ord);

  v_n := jsonb_array_length(v_files);
  if v_n > 2 then
    return json_build_object('ok', false, 'error', '最多上传 2 份文件（简历文件 + 图片）');
  end if;

  select coalesce(sum((x->>'size')::bigint), 0) into v_total
    from jsonb_array_elements(v_files) x;
  if v_total <= 0 then
    return json_build_object('ok', false, 'error', '请选择简历文件');
  end if;
  if exists (select 1 from jsonb_array_elements(v_files) x
              where coalesce((x->>'size')::bigint, 0) > 20 * 1024 * 1024) then
    return json_build_object('ok', false, 'error', '单个文件请控制在 20MB 以内');
  end if;
  if v_total > 30 * 1024 * 1024 then
    return json_build_object('ok', false, 'error', '文件总计请控制在 30MB 以内');
  end if;

  -- 同项目同姓名同手机号只能投一次
  if exists (select 1 from public.resumes
              where project_id = v_pid
                and lower(btrim(name)) = lower(v_name)
                and btrim(phone) = v_phone
                and complete = true) then
    return json_build_object('ok', false, 'duplicate', true,
                             'error', '你已投递过该项目的简历，无需重复提交');
  end if;

  -- 清掉同人上一次没传完的残留（只针对未完成的临时记录，不影响任何已完成简历）
  delete from public.resumes
   where project_id = v_pid and lower(btrim(name)) = lower(v_name)
     and btrim(phone) = v_phone and complete = false;

  v_first := v_files->0;
  insert into public.resumes (project_id, name, phone, email, intro,
                              file_name, file_type, file_size, files)
  values (v_pid, v_name, v_phone, coalesce(p_email, ''), coalesce(p_intro, ''),
          coalesce(v_first->>'name', ''), coalesce(v_first->>'type', ''),
          coalesce((v_first->>'size')::bigint, 0), v_files)
  returning * into v_row;

  return json_build_object('ok', true, 'id', v_row.id, 'count', v_n);
exception
  when unique_violation then
    return json_build_object('ok', false, 'duplicate', true,
                             'error', '你已投递过该项目的简历，无需重复提交');
end;
$$;

-- 旧签名（不带 p_files）会被上面这个新版本取代，删掉以免调用时出现歧义
drop function if exists public.resume_submit(text, text, text, text, text, text, text, bigint);

-- 13.2 投递第三步（重建）：分片数量与文件清单核对无误后才置为完成
create or replace function public.resume_submit_done(p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_row  public.resumes;
  v_n    int;
  v_need int;
begin
  if p_id is null then
    return json_build_object('ok', false, 'error', '参数错误');
  end if;
  select * into v_row from public.resumes where id = p_id and complete = false;
  if v_row.id is null then
    return json_build_object('ok', false, 'error', '投递记录不存在或已完成');
  end if;

  select count(*) into v_n from public.resume_parts where resume_id = p_id;
  if v_n = 0 then
    return json_build_object('ok', false, 'error', '文件尚未上传完成');
  end if;

  if jsonb_typeof(coalesce(v_row.files, '[]'::jsonb)) = 'array'
     and jsonb_array_length(coalesce(v_row.files, '[]'::jsonb)) > 0 then
    select coalesce(sum((x->>'parts')::int), 0) into v_need
      from jsonb_array_elements(v_row.files) x;
    if v_n < v_need then
      return json_build_object('ok', false, 'error', '文件尚未全部上传完成，请重试');
    end if;
  end if;

  update public.resumes set complete = true, parts = v_n where id = p_id;
  return json_build_object('ok', true, 'parts', v_n);
end;
$$;

-- 13.3 后台取文件内容（重建）：p_idx 指定取第几份文件；
--      老记录（files 为空）不分份，一律取全部分片，行为与第 9 节完全一致。
create or replace function public.resume_file(p_token text, p_id uuid, p_idx int default 0)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_row   public.resumes;
  v_data  text;
  v_files jsonb;
  v_i     int;
  v_start int := 0;
  v_len   int;
  v_f     jsonb;
  v_j     int;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  select * into v_row from public.resumes where id = p_id;
  if v_row.id is null then
    return json_build_object('ok', false, 'error', '简历不存在或已删除');
  end if;

  v_files := coalesce(v_row.files, '[]'::jsonb);

  if jsonb_typeof(v_files) <> 'array' or jsonb_array_length(v_files) = 0 then
    select coalesce(string_agg(chunk, '' order by seq), '') into v_data
      from public.resume_parts where resume_id = p_id;
    if coalesce(v_data, '') = '' then
      return json_build_object('ok', false, 'error', '文件内容缺失');
    end if;
    return json_build_object('ok', true, 'idx', 0, 'count', 1,
      'file_name', v_row.file_name, 'file_type', v_row.file_type,
      'file_size', v_row.file_size, 'data', v_data);
  end if;

  v_i := greatest(0, least(coalesce(p_idx, 0), jsonb_array_length(v_files) - 1));
  for v_j in 0 .. v_i - 1 loop
    v_start := v_start + coalesce((v_files->v_j->>'parts')::int, 0);
  end loop;
  v_f   := v_files->v_i;
  v_len := coalesce((v_f->>'parts')::int, 0);

  select coalesce(string_agg(chunk, '' order by seq), '') into v_data
    from public.resume_parts
   where resume_id = p_id and seq >= v_start
     and (v_len <= 0 or seq < v_start + v_len);
  if coalesce(v_data, '') = '' then
    return json_build_object('ok', false, 'error', '文件内容缺失');
  end if;

  return json_build_object('ok', true,
    'idx', v_i, 'count', jsonb_array_length(v_files),
    'file_name', coalesce(v_f->>'name', ''), 'file_type', coalesce(v_f->>'type', ''),
    'file_size', coalesce((v_f->>'size')::bigint, 0), 'data', v_data);
end;
$$;
drop function if exists public.resume_file(text, uuid);

-- 13.4 后台简历列表（重建）：把文件清单一起返回，后台可逐个预览 / 下载
create or replace function public.resume_list(p_token text, p_project_id text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_super boolean;
  v_pid   text;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期');
  end if;
  v_super := (v_admin.role = 'super');
  v_pid   := btrim(coalesce(p_project_id, ''));
  return json_build_object('ok', true, 'super', v_super, 'resumes', (
    select coalesce(json_agg(json_build_object(
      'id', r.id, 'project_id', r.project_id,
      'name', r.name, 'phone', r.phone, 'email', r.email, 'intro', r.intro,
      'file_name', r.file_name, 'file_type', r.file_type, 'file_size', r.file_size,
      'files', case
        when jsonb_typeof(coalesce(r.files, '[]'::jsonb)) = 'array'
             and jsonb_array_length(coalesce(r.files, '[]'::jsonb)) > 0
        then coalesce(r.files, '[]'::jsonb)
        else jsonb_build_array(jsonb_build_object(
               'name', r.file_name, 'type', r.file_type, 'size', r.file_size))
      end,
      'created_at', r.created_at,
      'dls', case when v_super then (
        select coalesce(json_agg(json_build_object('who', d.admin_name, 'at', d.created_at)
                                 order by d.created_at), '[]'::json)
          from public.resume_downloads d where d.resume_id = r.id
      ) else '[]'::json end
    ) order by r.created_at desc), '[]'::json)
    from public.resumes r
    where r.complete = true and (v_pid = '' or r.project_id = v_pid)
  ));
end;
$$;

-- 13.5 调用权限（与第 9 节一致，按新签名重新授权）
grant execute on function
  public.resume_submit(text, text, text, text, text, text, text, bigint, jsonb),
  public.resume_submit_done(uuid),
  public.resume_file(text, uuid, int),
  public.resume_list(text, text)
to anon, authenticated;

notify pgrst, 'reload schema';
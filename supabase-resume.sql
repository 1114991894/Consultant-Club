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
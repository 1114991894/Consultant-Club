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

-- ---------- 10. 管理员密码重置（总管理员在「管理员管理」里重设任意管理员密码） ----------

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
  return json_build_object('ok', true, 'phone', v_target.phone, 'name', v_target.name);
end;
$$;

-- 10.2 调用权限：与其它后台函数一致
grant execute on function public.admin_reset_password(text, uuid, text)
to anon, authenticated;

-- 让 PostgREST 立刻认识这些新函数（避免刚执行完调用报「找不到函数」）
notify pgrst, 'reload schema';
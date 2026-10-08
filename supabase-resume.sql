-- ---------- 16. 咨询师个人简历（工作台「个人中心」上传 / 删除 / 替换，并可一键投递） ----------
-- 背景：咨询师在官网投递简历时每次都要重新选文件、重新填姓名手机号。这里让他在自己的工作台
--      先存一份自己的简历（最多 2 份：简历文件 + 图片），之后不管是在个人中心看最新项目，
--      还是登录后在官网项目页，都能「一键投递」——点一下、确认，就完成投递。
-- 文件规则与官网投递完全一致：支持 PDF / Word / 图片，单个文件 ≤ 20MB、总计 ≤ 30MB，
--      图片在前端自动压到 1MB 以内；文件正文按 600KB 一片存进来，读取时按 seq 顺序拼回，
--      内容不会被改动或损伤。
-- 一键投递的结果就是一条普通的 resumes 记录（连同文件分片一起复制过去），
--      所以后台「项目管理 → 查看简历」的预览 / 下载 / 留痕流程完全不用改。
-- 本节只新建表与新函数，不做任何 update / delete 既有业务表，历史数据一律保留、不动。

-- 16.1 咨询师简历主表：一个咨询师可能有多行，取最新一条 complete = true 的作为当前简历。
--      「替换」= 新的一份传完后再删掉旧的，中途失败旧简历不受影响。
create table if not exists public.consultant_resumes (
  id         uuid primary key default gen_random_uuid(),
  admin_id   uuid not null references public.admins(id) on delete cascade,
  files      jsonb not null default '[]'::jsonb,   -- [{name,type,size,parts}]
  parts      int not null default 0,
  complete   boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists consultant_resumes_idx
  on public.consultant_resumes (admin_id, created_at desc);

-- 16.2 分片表：与 resume_parts 结构一致，按 600KB 一片存
create table if not exists public.consultant_resume_parts (
  owner_id uuid not null references public.consultant_resumes(id) on delete cascade,
  seq      int  not null,
  chunk    text not null,
  primary key (owner_id, seq)
);

-- 16.3 RLS：两张表都不建 policy → 匿名与登录用户都无法直接读写，只能走下面的 security definer 函数
alter table public.consultant_resumes      enable row level security;
alter table public.consultant_resume_parts enable row level security;

-- 16.4 上传第一步：登记本次要传的文件清单，返回 id
create or replace function public.consultant_resume_begin(p_token text, p_files jsonb)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me    public.admins;
  v_files jsonb;
  v_total bigint;
  v_row   public.consultant_resumes;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;

  v_files := coalesce(p_files, '[]'::jsonb);
  if jsonb_typeof(v_files) <> 'array' or jsonb_array_length(v_files) = 0 then
    return json_build_object('ok', false, 'error', '请选择简历文件');
  end if;
  if jsonb_array_length(v_files) > 2 then
    return json_build_object('ok', false, 'error', '最多上传 2 份文件（简历文件 + 图片）');
  end if;

  -- 规整每一份文件，并按「600KB 一片」算出分片数（与官网投递规则一致）
  select jsonb_agg(jsonb_build_object(
           'name',  coalesce(nullif(btrim(x->>'name'), ''), '简历'),
           'type',  coalesce(x->>'type', ''),
           'size',  coalesce((x->>'size')::bigint, 0),
           'parts', greatest(1, ceil(coalesce((x->>'size')::bigint, 0)::numeric / 614400)::int)
         ) order by ord)
    into v_files
    from jsonb_array_elements(v_files) with ordinality as t(x, ord);

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

  -- 清掉上一次没传完的残留（已完成的旧简历保留，等新的一份传完再替换）
  delete from public.consultant_resumes where admin_id = v_me.id and complete = false;

  insert into public.consultant_resumes (admin_id, files)
  values (v_me.id, v_files)
  returning * into v_row;

  return json_build_object('ok', true, 'id', v_row.id);
end;
$$;

-- 16.5 上传第二步：逐片写入（只能写自己名下、还没完成的记录）
create or replace function public.consultant_resume_part_add(
  p_token text, p_id uuid, p_seq int, p_chunk text
) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me public.admins;
  v_ok boolean;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if p_id is null or p_seq is null or p_seq < 0 then
    return json_build_object('ok', false, 'error', '参数错误');
  end if;
  if length(coalesce(p_chunk, '')) > 1500000 then
    return json_build_object('ok', false, 'error', '单个分片过大');
  end if;
  select true into v_ok from public.consultant_resumes
   where id = p_id and admin_id = v_me.id and complete = false;
  if v_ok is null then
    return json_build_object('ok', false, 'error', '上传记录不存在或已完成');
  end if;
  insert into public.consultant_resume_parts (owner_id, seq, chunk)
  values (p_id, p_seq, p_chunk)
  on conflict (owner_id, seq) do update set chunk = excluded.chunk;
  return json_build_object('ok', true);
end;
$$;

-- 16.6 上传第三步：分片齐了才置为完成；随后删掉旧简历（这一步就是「替换」）
create or replace function public.consultant_resume_done(p_token text, p_id uuid)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me   public.admins;
  v_row  public.consultant_resumes;
  v_n    int;
  v_need int;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  select * into v_row from public.consultant_resumes
   where id = p_id and admin_id = v_me.id and complete = false;
  if v_row.id is null then
    return json_build_object('ok', false, 'error', '上传记录不存在或已完成');
  end if;

  select count(*) into v_n from public.consultant_resume_parts where owner_id = p_id;
  if v_n = 0 then
    return json_build_object('ok', false, 'error', '文件尚未上传完成');
  end if;
  select coalesce(sum((x->>'parts')::int), 0) into v_need
    from jsonb_array_elements(coalesce(v_row.files, '[]'::jsonb)) x;
  if v_n < v_need then
    return json_build_object('ok', false, 'error', '文件尚未全部上传完成，请重试');
  end if;

  update public.consultant_resumes set complete = true, parts = v_n where id = p_id;

  delete from public.consultant_resumes
   where admin_id = v_me.id and complete = true and id <> p_id;

  return json_build_object('ok', true, 'parts', v_n);
end;
$$;

-- 16.7 读取：当前简历的清单与总大小（没传过返回 has = false）
create or replace function public.consultant_resume_get(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me  public.admins;
  v_row public.consultant_resumes;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  select * into v_row from public.consultant_resumes
   where admin_id = v_me.id and complete = true
   order by created_at desc limit 1;
  if v_row.id is null then
    return json_build_object('ok', true, 'has', false, 'files', '[]'::json);
  end if;
  return json_build_object('ok', true, 'has', true,
    'id', v_row.id, 'files', v_row.files, 'parts', v_row.parts,
    'size', (select coalesce(sum((x->>'size')::bigint), 0)
               from jsonb_array_elements(v_row.files) x),
    'updated_at', v_row.created_at);
end;
$$;

-- 16.8 删除：把自己名下的简历（含分片）全部删掉
create or replace function public.consultant_resume_delete(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare v_me public.admins;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  delete from public.consultant_resumes where admin_id = v_me.id;
  return json_build_object('ok', true);
end;
$$;

-- 16.9 一键投递：把个人中心里的简历复制成一条正常的 resumes 记录（姓名 / 手机号取登录账号）
create or replace function public.consultant_resume_submit(p_token text, p_project_id text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me    public.admins;
  v_pid   text;
  v_name  text;
  v_phone text;
  v_src   public.consultant_resumes;
  v_card  public.consultants;
  v_first jsonb;
  v_intro text;
  v_new   uuid;
  v_n     int;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null or v_me.role <> 'consultant' then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;

  v_pid := btrim(coalesce(p_project_id, ''));
  if v_pid = '' then
    return json_build_object('ok', false, 'error', '项目参数缺失，请刷新页面后重试');
  end if;
  if not exists (select 1 from public.projects where project_id = v_pid) then
    return json_build_object('ok', false, 'error', '项目不存在或已下线，请刷新页面后重试');
  end if;

  select * into v_card from public.consultants where admin_id = v_me.id limit 1;
  v_name  := coalesce(nullif(btrim(coalesce(v_me.name, '')), ''),
                      nullif(btrim(coalesce(v_card.name, '')), ''), '咨询师');
  v_phone := btrim(coalesce(v_me.phone, ''));
  if v_phone !~ '^1[0-9]{10}$' then
    return json_build_object('ok', false, 'error', '账号手机号异常，请联系管理员');
  end if;

  select * into v_src from public.consultant_resumes
   where admin_id = v_me.id and complete = true
   order by created_at desc limit 1;
  if v_src.id is null then
    return json_build_object('ok', false, 'no_resume', true,
      'error', '请先在个人中心上传简历，再一键投递');
  end if;

  if exists (select 1 from public.resumes
              where project_id = v_pid
                and lower(btrim(name)) = lower(v_name)
                and btrim(phone) = v_phone
                and complete = true) then
    return json_build_object('ok', false, 'duplicate', true,
      'error', '你已投递过该项目的简历，无需重复提交');
  end if;

  delete from public.resumes
   where project_id = v_pid and lower(btrim(name)) = lower(v_name)
     and btrim(phone) = v_phone and complete = false;

  v_first := coalesce(v_src.files->0, '{}'::jsonb);
  v_intro := coalesce(nullif(btrim(coalesce(v_card.profile->>'experience', '')), ''),
                      nullif(btrim(coalesce(v_card.bio, '')), ''), '');

  insert into public.resumes (project_id, name, phone, email, intro,
                              file_name, file_type, file_size, files, parts, complete)
  values (v_pid, v_name, v_phone,
          coalesce(nullif(btrim(coalesce(v_card.profile->>'email', '')), ''), ''),
          v_intro,
          coalesce(v_first->>'name', ''), coalesce(v_first->>'type', ''),
          coalesce((v_first->>'size')::bigint, 0),
          v_src.files, 0, false)
  returning id into v_new;

  insert into public.resume_parts (resume_id, seq, chunk)
  select v_new, seq, chunk from public.consultant_resume_parts where owner_id = v_src.id;

  select count(*) into v_n from public.resume_parts where resume_id = v_new;
  if v_n = 0 then
    delete from public.resumes where id = v_new;
    return json_build_object('ok', false, 'error', '简历文件缺失，请重新上传后再投递');
  end if;
  update public.resumes set complete = true, parts = v_n where id = v_new;

  return json_build_object('ok', true, 'id', v_new,
                           'count', jsonb_array_length(v_src.files));
exception
  when unique_violation then
    return json_build_object('ok', false, 'duplicate', true,
      'error', '你已投递过该项目的简历，无需重复提交');
end;
$$;

-- 16.10 重建「投递项目」列表：只统计已完成（complete = true）的投递，
--       避免中途失败的临时记录混进来（第 11 节的版本漏了这个条件）
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
         and r.complete = true
    ) t;
  exception when undefined_table then
    v_js := '[]'::json;      -- 简历功能还没建表时不报错，返回空
  end;
  return json_build_object('ok', true, 'projects', v_js);
end;
$$;

-- 16.11 调用权限（一律走 security definer 函数，表本身不开放）
grant execute on function
  public.consultant_resume_begin(text, jsonb),
  public.consultant_resume_part_add(text, uuid, int, text),
  public.consultant_resume_done(text, uuid),
  public.consultant_resume_get(text),
  public.consultant_resume_delete(text),
  public.consultant_resume_submit(text, text)
to anon, authenticated;

notify pgrst, 'reload schema';
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

-- ---------- 14. 后台「数据总览」列表改走函数读取 ----------
-- 原实现：前端带着 x-admin-token 直接读 submissions 表，靠 RLS 策略
--   using (admin_from_token(current_setting('request.headers', true)::json->>'x-admin-token') is not null)
-- 放行。该策略要求 PostgREST 把自定义请求头注入 request.headers 这个 GUC。
-- 在部分环境里（PostgREST 升级、或项目设置了 db-pre-request）该注入会失效，症状是：
--   携带有效 token 也返回 200 + 空数组 —— 后台列表整个空白、四个统计数字全是 0，
--   但「未处理」角标却有正确数字（角标走的是 security definer 函数）。
-- 这里按项目既有约定（后台读写一律 security definer 函数 + admin_from_token）
-- 改为函数读取，不再依赖请求头；RLS 策略一并重建，两种读法都保活。
-- 本节不含任何 insert / update / delete，可重复执行。

create or replace function public.admin_submissions(p_token text)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_me   public.admins;
  v_list json;
begin
  v_me := admin_from_token(p_token);
  if v_me.id is null then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if v_me.role = 'consultant' then
    return json_build_object('ok', false, 'error', '无权限查看');
  end if;
  -- 用 to_jsonb 整行序列化，不写死列名，数据库未升级（缺 status / handler_* 等列）时也不会报错
  select coalesce(json_agg(to_jsonb(t) order by t.created_at desc), '[]'::json)
    into v_list
    from (select * from public.submissions order by created_at desc limit 1000) t;
  return json_build_object('ok', true, 'list', v_list);
end;
$$;

grant execute on function public.admin_submissions(text) to anon, authenticated;

-- 14.2 自检：确认 PostgREST 是否还在注入请求头（只回布尔，不外泄任何内容）
create or replace function public.admin_self_check()
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_raw text;
  v_val text;
begin
  v_raw := current_setting('request.headers', true);
  if v_raw is null then
    return json_build_object('headers_available', false, 'token_seen', false);
  end if;
  begin
    v_val := coalesce(v_raw::json->>'x-admin-token', '');
  exception when others then
    v_val := '';
  end;
  return json_build_object('headers_available', true, 'token_seen', v_val <> '');
end;
$$;

grant execute on function public.admin_self_check() to anon, authenticated;

-- 14.3 RLS 策略重建（幂等，写法与第 3 节一致；请求头注入恢复后直读仍可用）
drop policy if exists submissions_admin_read on public.submissions;
create policy submissions_admin_read on public.submissions
  for select to anon, authenticated using (
    admin_from_token(current_setting('request.headers', true)::json->>'x-admin-token') is not null
  );

notify pgrst, 'reload schema';
-- ---------- 15. 咨询师申请去重（同一姓名 + 同一手机号只能申请一次） ----------
-- 背景：咨询师申请是直接 insert 进 submissions（type='apply'），匿名只能写、不能读这张表，
--      所以前端无论如何都查不到「我是不是已经投过」，只能由数据库来判。
-- 做法两层：
--   15.1 consultant_apply_check() 给前端做提交前校验（匿名可执行），命中就提示，不产生新记录；
--   15.2 before insert 触发器兜底：万一前端被绕过（旧缓存、直接调接口），数据库直接拦下并报 23505。
-- 判定口径：type='apply' 且 姓名（忽略大小写与首尾空格）+ 手机号 完全相同。
-- 本节不含任何 update / delete / drop table，历史记录一律保留、不动。

-- 15.1 提交前校验（只回布尔，不返回任何申请内容）
create or replace function public.consultant_apply_check(p_name text, p_phone text)
returns boolean
language sql stable security definer set search_path = public, extensions as $$
  select
    btrim(coalesce(p_name, '')) <> ''
    and btrim(coalesce(p_phone, '')) <> ''
    and exists (
      select 1 from public.submissions s
      where s.type = 'apply'
        and lower(btrim(coalesce(s.data->>'name', '')))  = lower(btrim(coalesce(p_name, '')))
        and btrim(coalesce(s.data->>'phone', ''))        = btrim(coalesce(p_phone, ''))
    )
$$;

grant execute on function public.consultant_apply_check(text, text) to anon, authenticated;

-- 15.2 触发器兜底（幂等：先 drop 再建）
create or replace function public.submissions_apply_dedup()
returns trigger
language plpgsql security definer set search_path = public, extensions as $$
begin
  if new.type = 'apply' then
    if btrim(coalesce(new.data->>'phone', '')) <> ''
       and exists (
         select 1 from public.submissions s
         where s.type = 'apply'
           and s.id <> new.id
           and lower(btrim(coalesce(s.data->>'name', ''))) = lower(btrim(coalesce(new.data->>'name', '')))
           and btrim(coalesce(s.data->>'phone', ''))       = btrim(coalesce(new.data->>'phone', ''))
       )
    then
      raise exception 'DUPLICATE_APPLY'
        using errcode = '23505',
              hint = '同一姓名、同一手机号只能申请一次';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_submissions_apply_dedup on public.submissions;
create trigger trg_submissions_apply_dedup
  before insert on public.submissions
  for each row execute function public.submissions_apply_dedup();

notify pgrst, 'reload schema';
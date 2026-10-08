-- ---------- 17. 项目自定义分类 ----------
-- 后台「新建 / 修改项目」的分类下拉，除内置分类外还能自己新增一个。
-- 自定义分类存在这张表里：后台下拉与官网「最近咨询项目」的筛选栏都会同步出现。
-- 表内只有分类名，不含任何个人信息，因此开放匿名只读。

-- 17.1 分类表
create table if not exists public.project_categories (
  id         bigserial primary key,
  name       text not null,
  sort       integer not null default 100,
  created_at timestamptz not null default now(),
  created_by text
);

-- 同名（忽略大小写与首尾空格）只允许一条
create unique index if not exists project_categories_name_key
  on public.project_categories (lower(btrim(name)));

create index if not exists project_categories_sort_idx
  on public.project_categories (sort, created_at);

-- 17.2 RLS：只开放「读」（官网筛选栏要用），写一律走下面的安全函数
alter table public.project_categories enable row level security;

drop policy if exists project_categories_read on public.project_categories;
create policy project_categories_read on public.project_categories
  for select to anon, authenticated using (true);

grant select on public.project_categories to anon, authenticated;

-- 17.3 读取全部分类（公开：官网筛选栏与后台下拉共用）
create or replace function public.project_categories_list()
returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce(
    jsonb_agg(jsonb_build_object('name', c.name) order by c.sort, c.created_at, c.name),
    '[]'::jsonb)
  from public.project_categories c
$$;

-- 17.4 新增分类（仅后台管理员；重名不报错，直接把已有的那条返回给前端选中）
create or replace function public.project_category_add(p_token text, p_name text)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_admin public.admins;
  v_name  text;
  v_exist text;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return jsonb_build_object('ok', false, 'error', '登录已失效，请重新登录');
  end if;

  v_name := btrim(coalesce(p_name, ''));
  v_name := regexp_replace(v_name, '[[:space:]]+', ' ', 'g');
  if v_name = '' then
    return jsonb_build_object('ok', false, 'error', '请先填写分类名称');
  end if;
  if char_length(v_name) > 12 then
    return jsonb_build_object('ok', false, 'error', '分类名称最多 12 个字');
  end if;

  select c.name into v_exist
    from public.project_categories c
   where lower(btrim(c.name)) = lower(v_name)
   limit 1;
  if v_exist is not null then
    return jsonb_build_object('ok', true, 'name', v_exist, 'dup', true);
  end if;

  insert into public.project_categories (name, created_by)
  values (v_name, v_admin.phone);

  return jsonb_build_object('ok', true, 'name', v_name, 'dup', false);
end;
$$;

-- 17.5 调用权限
grant execute on function public.project_categories_list() to anon, authenticated;
grant execute on function public.project_category_add(text, text) to anon, authenticated;

notify pgrst, 'reload schema';
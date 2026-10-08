-- ---------- 18. 首页展示开关（同意只开通账号，上不上首页由开关决定） ----------
-- 原来「数据总览 → 咨询师申请」点「同意」会连带把人插进首页「项目咨询师」
-- 模块，等于审批动作 = 对外公开。现在拆成两步：
--   ① 同意 = 只开通咨询师个人管理后台（登录账号 + 初始密码）；
--   ② 是否挂到官网首页，由「咨询师管理」每行的「首页展示」开关决定。
--
-- 本节只用 add column / create index / create function / grant，
-- 唯一的 update 只在「新列刚加上、值还是 null」时执行一次（把眼下已经在
-- 首页展示的那批人标记为展示中，不让任何一位凭空消失）；
-- 不删除、不覆盖任何已有数据，可重复执行。
-- 18.1 先加可空列：不加默认值，才能区分「从未设置过」和「管理员手动关掉」
alter table public.consultants add column if not exists home_listed boolean;

-- 18.2 已经在首页展示的人保持展示（只在 null 时跑一次，之后不会再动）
update public.consultants set home_listed = true where home_listed is null;

-- 18.3 此后新建的卡片（同意申请、咨询师自己完善资料）默认「不在首页展示」
alter table public.consultants alter column home_listed set default false;
alter table public.consultants alter column home_listed set not null;
create index if not exists consultants_home_listed_idx on public.consultants (home_listed);

-- 18.4 官网首页要按这一列过滤，单独放开这一列的读权限（只是个展示开关，
--      不含任何个人信息；其余列仍按第 12 节那样逐列授权）
grant select (home_listed) on public.consultants to anon, authenticated;

-- 18.5 后台上 / 下首页展示（需管理员 token）
create or replace function public.consultant_home_set(p_token text, p_id uuid, p_on boolean)
returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_admin public.admins;
  v_on    boolean;
begin
  v_admin := admin_from_token(p_token);
  if v_admin.id is null then
    return json_build_object('ok', false, 'error', '登录已过期，请重新登录');
  end if;
  if v_admin.role not in ('super','admin') then
    return json_build_object('ok', false, 'error', '无权限操作');
  end if;

  v_on := coalesce(p_on, false);
  update public.consultants set home_listed = v_on where id = p_id;
  if not found then
    return json_build_object('ok', false, 'error', '咨询师不存在或已删除');
  end if;
  return json_build_object('ok', true, 'id', p_id, 'home_listed', v_on);
end;
$$;

-- 18.6 后台「＋ 添加咨询师」本身就是「我要把这个人加到官网」的动作，
--      保持原来的体验：新建即展示；编辑资料时不动这个开关。
--      （同意申请走的是 consultant_apply_approve，不经过这里，默认不展示）
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
    insert into public.consultants (name, title, bio, image, home_listed)
    values (p_name, p_title, coalesce(p_bio, ''), p_image, true)
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

-- 18.7 调用权限
grant execute on function public.consultant_home_set(text, uuid, boolean) to anon, authenticated;

notify pgrst, 'reload schema';
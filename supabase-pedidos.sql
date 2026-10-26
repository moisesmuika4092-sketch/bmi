-- BMI: registo de contas com aprovação do administrador
create table if not exists public.pedidos (
  uid uuid primary key references auth.users(id) on delete cascade,
  email text,
  nome text,
  criado timestamptz default now()
);
alter table public.pedidos enable row level security;

create or replace function public.bmi_is_admin() returns boolean
language sql security definer set search_path = public stable
as $$ select coalesce((select admin from public.perfis where uid = auth.uid() limit 1), false) $$;

drop policy if exists pedidos_insert on public.pedidos;
create policy pedidos_insert on public.pedidos for insert to authenticated
  with check (uid = auth.uid());

drop policy if exists pedidos_select on public.pedidos;
create policy pedidos_select on public.pedidos for select to authenticated
  using (uid = auth.uid() or public.bmi_is_admin());

create or replace function public.aprovar_pedido(p uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.bmi_is_admin() then raise exception 'Sem permissão'; end if;
  insert into public.perfis(uid, admin)
    select p, false where not exists (select 1 from public.perfis where uid = p);
  delete from public.pedidos where uid = p;
end $$;

create or replace function public.rejeitar_pedido(p uuid) returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if not public.bmi_is_admin() then raise exception 'Sem permissão'; end if;
  delete from public.pedidos where uid = p;
  delete from auth.users where id = p
    and not exists (select 1 from public.perfis where uid = p);
end $$;

revoke all on function public.aprovar_pedido(uuid), public.rejeitar_pedido(uuid) from public, anon;
grant execute on function public.aprovar_pedido(uuid), public.rejeitar_pedido(uuid) to authenticated;

alter publication supabase_realtime add table public.pedidos;

-- Migração: revogação da visibilidade admin (Termos de Uso, seção
-- "Visibilidade de Dados Durante o Beta").
-- Rode isso no SQL Editor do painel do Supabase (Project → SQL Editor → New query).
-- Idempotente: pode rodar mais de uma vez sem erro. Pré-requisito:
-- migration_6_cadastro_termos.sql (tabela profiles).
--
-- profiles.visivel_para_admin = false  →  o usuário some de TUDO que uma
-- conta admin enxerga: as 5 policies select_own_or_admin e o admin_report().
-- O próprio usuário continua vendo os próprios dados normalmente (o ramo
-- auth.uid() = user_id das policies não muda).
--
-- Ainda sem UI: a revogação é feita à mão, pelo SQL Editor, quando alguém
-- pedir pelo e-mail de contato do termo:
--
--   insert into public.profiles (user_id, visivel_para_admin)
--   select id, false from auth.users where email = 'pessoa@exemplo.com'
--   on conflict (user_id) do update set visivel_para_admin = false;
--
-- (insert ... on conflict em vez de update puro: funciona mesmo se, por
-- algum motivo, o usuário ainda não tiver linha em profiles.)

begin;

-- 1. Coluna
alter table public.profiles
  add column if not exists visivel_para_admin boolean not null default true;

-- 2. Helper usado pelas policies.
-- SECURITY DEFINER é obrigatório aqui: se a policy de expenses (etc.)
-- consultasse profiles direto, essa leitura passaria pela RLS de profiles
-- — que esconde justamente a linha do usuário oculto — e o NOT EXISTS/
-- coalesce concluiria "visível", anulando a revogação. Na policy da
-- própria profiles, a consulta direta ainda daria recursão infinita.
-- Usuário sem linha em profiles = visível (default do termo).
create or replace function public.visivel_para_admin(uid uuid)
returns boolean
language sql
stable
security definer
set search_path to 'public'
as $$
  select coalesce(
    (select p.visivel_para_admin from public.profiles p where p.user_id = uid),
    true
  );
$$;

revoke all on function public.visivel_para_admin(uuid) from public, anon;
grant execute on function public.visivel_para_admin(uuid) to authenticated;

-- 3. As 5 policies de SELECT: mesmo texto de antes + a condição nova no
-- ramo admin.
drop policy if exists select_own_or_admin on public.categories;
create policy select_own_or_admin
  on public.categories
  as permissive
  for select
  to authenticated
  using (
    (auth.uid() = user_id)
    or (
      (auth.uid() in (select admin_users.user_id from admin_users))
      and public.visivel_para_admin(user_id)
    )
  );

drop policy if exists select_own_or_admin on public.expenses;
create policy select_own_or_admin
  on public.expenses
  as permissive
  for select
  to authenticated
  using (
    (auth.uid() = user_id)
    or (
      (auth.uid() in (select admin_users.user_id from admin_users))
      and public.visivel_para_admin(user_id)
    )
  );

drop policy if exists select_own_or_admin on public.extra_incomes;
create policy select_own_or_admin
  on public.extra_incomes
  as permissive
  for select
  to authenticated
  using (
    (auth.uid() = user_id)
    or (
      (auth.uid() in (select admin_users.user_id from admin_users))
      and public.visivel_para_admin(user_id)
    )
  );

drop policy if exists select_own_or_admin on public.monthly_balances;
create policy select_own_or_admin
  on public.monthly_balances
  as permissive
  for select
  to authenticated
  using (
    (auth.uid() = user_id)
    or (
      (auth.uid() in (select admin_users.user_id from admin_users))
      and public.visivel_para_admin(user_id)
    )
  );

drop policy if exists select_own_or_admin on public.profiles;
create policy select_own_or_admin
  on public.profiles
  as permissive
  for select
  to authenticated
  using (
    (auth.uid() = user_id)
    or (
      (auth.uid() in (select admin_users.user_id from admin_users))
      and public.visivel_para_admin(user_id)
    )
  );

-- 4. admin_report(): mesmo corpo de db_schema_atual.sql (snapshot de
-- 2026-09-16) + left join em profiles e o filtro no select final.
-- Obs.: se um admin ocultar a si mesmo e for o único usuário visível, o
-- relatório volta vazio e o admin.html o trata como não-admin.
CREATE OR REPLACE FUNCTION public.admin_report()
 RETURNS TABLE(user_id uuid, email text, saldo_inicial numeric, total_gastos numeric, categorias jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if not exists (select 1 from public.admin_users a where a.user_id = auth.uid()) then
    return;
  end if;

  return query
  with mes_atual as (
    select date_trunc('month', current_date)::date as ref
  ),
  por_categoria as (
    select
      e.user_id,
      coalesce(c.nome, e.categoria_id) as categoria_nome,
      sum(e.valor) as valor_categoria
    from public.expenses e
    left join public.categories c
      on c.category_key = e.categoria_id and c.user_id = e.user_id
    where e.mes_referencia = (select ref from mes_atual)
    group by e.user_id, coalesce(c.nome, e.categoria_id)
  ),
  agregado_por_usuario as (
    select
      pc.user_id,
      sum(pc.valor_categoria) as total_gastos,
      jsonb_agg(
        jsonb_build_object('categoria', pc.categoria_nome, 'valor', pc.valor_categoria)
        order by pc.valor_categoria desc
      ) as categorias
    from por_categoria pc
    group by pc.user_id
  )
  select
    u.id::uuid as user_id,
    u.email::text as email,
    coalesce(mb.saldo_inicial, 0)::numeric as saldo_inicial,
    coalesce(apu.total_gastos, 0)::numeric as total_gastos,
    coalesce(apu.categorias, '[]'::jsonb) as categorias
  from auth.users u
  left join agregado_por_usuario apu on apu.user_id = u.id
  left join public.monthly_balances mb
    on mb.user_id = u.id and mb.mes_referencia = (select ref from mes_atual)
  left join public.profiles pf on pf.user_id = u.id
  where coalesce(pf.visivel_para_admin, true)
  order by coalesce(apu.total_gastos, 0) desc, u.email asc;
end;
$function$;

commit;

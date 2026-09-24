-- Fonte de verdade do schema de segurança atual (função admin + RLS).
--
-- Extraído do SQL Editor do Supabase em 2026-09-16, colando o resultado de:
--   select pg_get_functiondef('public.admin_report'::regproc);
--   select tablename, policyname, permissive, roles, cmd, qual, with_check
--     from pg_policies
--     where tablename in ('categories','expenses','monthly_balances','extra_incomes')
--     order by tablename, policyname;
--
-- Este arquivo é só documentação/rastreamento (snapshot do estado real do
-- banco na data acima) — não é uma migração pra rodar. Se a função ou as
-- policies mudarem no Supabase, atualize este arquivo rodando as duas
-- queries acima de novo e substituindo o conteúdo correspondente, pra
-- manter isso como fonte de verdade versionada. Ver SECURITY_AUDIT.md
-- pra o contexto da auditoria que motivou este arquivo.
--
-- ATUALIZADO em 2026-09-24 à mão, a partir de migration_6_cadastro_termos.sql
-- e migration_7_visibilidade_admin.sql (tabela profiles, helper
-- visivel_para_admin(), policies select_own_or_admin e admin_report() com o
-- filtro de visibilidade). NÃO foi re-extraído do banco — rode de novo as
-- queries acima (incluindo 'profiles' na lista de tabelas) pra confirmar
-- que o estado real bate com este arquivo.

-- ============================================================
-- Tabela de apoio referenciada pelas policies e pela função.
-- Estrutura completa não foi introspectada nesta auditoria — só se
-- confirmou que ela existe e que a coluna relevante é `user_id`
-- (é o que aparece em `admin_users.user_id` nas queries abaixo).
-- Quem está nessa tabela é quem o app trata como admin.
-- ============================================================
-- table public.admin_users ( user_id uuid ..., ... )


-- ============================================================
-- FUNÇÃO: public.admin_report()
--
-- SECURITY DEFINER + SET search_path fixo em 'public' (protege contra
-- search_path hijacking, boa prática pra função SECURITY DEFINER).
--
-- A primeira linha do corpo já resolve a autorização: se auth.uid() não
-- estiver em admin_users, a função retorna sem nenhuma linha (RETURN
-- vazio) — nunca chega a montar a query que lê auth.users/expenses/etc.
-- Confirmado também por teste dinâmico (ver SECURITY_AUDIT.md item a):
-- duas contas não autorizadas receberam HTTP 200 com corpo [].
-- ============================================================

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


-- ============================================================
-- TABELA profiles (migration_6) + visibilidade admin (migration_7)
--
-- 1 linha por usuário, criada pelo trigger on_auth_user_created_profile
-- no insert de auth.users (telefone e aceite vêm do user_metadata do
-- signUp; aceitou_termos_em = now() do servidor). Client só lê a própria
-- linha — sem policy de insert/update/delete.
--
-- visivel_para_admin = false tira o usuário de tudo que uma conta admin
-- vê (5 policies + admin_report). Revogação manual pelo SQL Editor — ver
-- o comando no topo de migration_7_visibilidade_admin.sql.
-- ============================================================

create table public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  telefone text,
  aceitou_termos_em timestamptz,
  created_at timestamptz not null default now(),
  visivel_para_admin boolean not null default true
);

-- SECURITY DEFINER de propósito: lida pelas policies, precisa enxergar a
-- linha de profiles mesmo quando a RLS de profiles a esconderia do admin.
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

create or replace function public.handle_new_user_profile()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  meta jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
begin
  insert into public.profiles (user_id, telefone, aceitou_termos_em)
  values (
    new.id,
    nullif(left(regexp_replace(coalesce(meta->>'telefone', ''), '\D', '', 'g'), 11), ''),
    case when meta->>'aceitou_termos' = 'true' then now() else null end
  )
  on conflict (user_id) do nothing;
  return new;
end;
$$;

create trigger on_auth_user_created_profile
  after insert on auth.users
  for each row execute function public.handle_new_user_profile();

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


-- ============================================================
-- RLS POLICIES — categories
-- ============================================================

create policy categories_delete_own
  on public.categories
  as permissive
  for delete
  to public
  using (auth.uid() = user_id);

create policy categories_insert_own
  on public.categories
  as permissive
  for insert
  to public
  with check (auth.uid() = user_id);

create policy categories_update_own
  on public.categories
  as permissive
  for update
  to public
  using (auth.uid() = user_id);

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


-- ============================================================
-- RLS POLICIES — expenses
-- ============================================================

create policy expenses_delete_own
  on public.expenses
  as permissive
  for delete
  to public
  using (auth.uid() = user_id);

create policy expenses_insert_own
  on public.expenses
  as permissive
  for insert
  to public
  with check (auth.uid() = user_id);

create policy expenses_update_own
  on public.expenses
  as permissive
  for update
  to public
  using (auth.uid() = user_id);

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


-- ============================================================
-- RLS POLICIES — extra_incomes
-- ============================================================

create policy incomes_delete_own
  on public.extra_incomes
  as permissive
  for delete
  to public
  using (auth.uid() = user_id);

create policy incomes_insert_own
  on public.extra_incomes
  as permissive
  for insert
  to public
  with check (auth.uid() = user_id);

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


-- ============================================================
-- RLS POLICIES — monthly_balances
--
-- Observação: não existe policy de DELETE nesta tabela (só insert,
-- update e select_own_or_admin). Com RLS habilitada, ausência de
-- policy para um comando = esse comando fica negado por padrão pra
-- todo mundo. Bate com o uso real no app (index.html só dá upsert em
-- monthly_balances, nunca delete) — registrado aqui como observação,
-- não como falha.
-- ============================================================

create policy balances_insert_own
  on public.monthly_balances
  as permissive
  for insert
  to public
  with check (auth.uid() = user_id);

create policy balances_update_own
  on public.monthly_balances
  as permissive
  for update
  to public
  using (auth.uid() = user_id);

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

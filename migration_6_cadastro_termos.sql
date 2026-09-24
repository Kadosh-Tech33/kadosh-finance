-- Migração: telefone + registro de aceite dos Termos de Uso no cadastro.
-- Rode isso no SQL Editor do painel do Supabase (Project → SQL Editor → New query).
-- Idempotente: pode rodar mais de uma vez sem erro.
--
-- Por que uma tabela nova: as 4 tabelas existentes são por lançamento/mês;
-- nenhuma tem "1 linha por usuário" onde telefone e aceite caibam.
--
-- Como os dados chegam: o index.html manda telefone e aceitou_termos no
-- user_metadata do signUp (options.data). O trigger abaixo roda no MESMO
-- insert de auth.users e cria a linha em profiles — então o aceite nasce
-- junto com a conta, e aceitou_termos_em é o now() do servidor (não um
-- horário vindo do navegador). O client não tem policy de insert/update
-- em profiles: ele só lê a própria linha.

-- 1. Tabela
create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  telefone text,
  aceitou_termos_em timestamptz,  
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- 2. RLS — mesmo padrão das outras tabelas (própria linha, ou admin lê tudo)
drop policy if exists select_own_or_admin on public.profiles;
create policy select_own_or_admin
  on public.profiles
  as permissive
  for select
  to authenticated
  using (
    (auth.uid() = user_id)
    or (auth.uid() in (select admin_users.user_id from admin_users))
  );
-- Sem policy de insert/update/delete: nega por padrão pro client.

-- 3. Trigger no cadastro
create or replace function public.handle_new_user_profile()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  meta jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
begin
  -- Nunca levanta erro: um erro aqui derrubaria o cadastro inteiro
  -- ("Database error saving new user"). Dado ausente/inválido vira null.
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

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
  after insert on auth.users
  for each row execute function public.handle_new_user_profile();

-- 4. Usuários que já existiam: uma linha vazia pra cada (sem telefone e
-- SEM aceite registrado — eles nunca aceitaram estes termos).
insert into public.profiles (user_id)
select id from auth.users
on conflict (user_id) do nothing;

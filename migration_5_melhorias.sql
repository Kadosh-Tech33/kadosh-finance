-- Migração para as 5 melhorias do Kadosh Finance.
-- Rode isso no SQL Editor do painel do Supabase (Project → SQL Editor → New query).
-- Idempotente: pode rodar mais de uma vez sem erro.

-- 1. Status de pagamento (cosmético — não entra em nenhum cálculo de saldo)
alter table public.expenses
  add column if not exists is_paid boolean not null default false;

-- 4b. Classificação Fixo/Variável por lançamento (opcional, herda da categoria se nulo)
alter table public.expenses
  add column if not exists classificacao text;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'expenses_classificacao_check'
  ) then
    alter table public.expenses
      add constraint expenses_classificacao_check
      check (classificacao is null or classificacao in ('Fixo', 'Variável'));
  end if;
end $$;

-- 2 e 3. Meta com alvo opcional: categories.valor_alvo já é nullable no banco
-- atual (confirmado) — nenhuma alteração de schema necessária aqui.

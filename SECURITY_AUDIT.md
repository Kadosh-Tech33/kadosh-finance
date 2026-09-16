# Auditoria de Segurança — Kadosh Finance

**Data:** 2026-09-16
**Escopo:** Isolamento de dados por usuário (RLS) e controle de acesso do painel admin, após as 5 melhorias implementadas (status de pagamento, classificação Fixo/Variável, etc.) e a migração do projeto para um repositório git real em `C:\Projetos\kadosh-finance`.
**Commit auditado:** `65397a3` (branch `main`, working tree limpo no momento da auditoria).

## Metodologia

Auditoria estática (leitura de código) + teste dinâmico black-box contra o projeto Supabase real (`jfzcmofigewimasmhvfs`), usando a `anon key` pública já embutida em `index.html`/`historico.html`/`admin.html` (é a mesma chave que o app usa no navegador do usuário final — não é um segredo).

Foram criadas duas contas de teste descartáveis via `POST /auth/v1/signup`:

- `audit.test.a.<timestamp>@kadoshtest.invalid`
- `audit.test.b.<timestamp>@kadoshtest.invalid`

Com elas, chamadas reais foram feitas contra `PostgREST` (`/rest/v1/...`) e a RPC `admin_report`, simulando um atacante que ignora o client JS e fala direto com a API — o cenário que realmente importa, já que a proteção do client (`.eq('user_id', currentUser.id)`) é cosmética e não pode ser a única linha de defesa.

Todos os dados de teste inseridos foram removidos ao final (confirmado por releitura). As duas contas de teste **não foram excluídas** (a anon key não tem permissão para deletar usuários — isso exigiria a `service_role` key, que não existe neste repositório nem foi usada nesta auditoria). Ficam registradas aqui para référencia: IDs `f7f4519a-6a1b-4b3a-b821-9af957dea0b4` (A) e `4943e784-56ae-4470-a069-d56f1165bd4a` (B). Recomenda-se removê-las depois pelo painel do Supabase (Authentication → Users) se isso incomodar.

---

## (a) admin.html / RPC `admin_report()`

**Verificado — texto exato da função (agora versionado em [`db_schema_atual.sql`](db_schema_atual.sql)):**
- `admin_report()` é `SECURITY DEFINER` com `SET search_path TO 'public'` fixo (boa prática contra search_path hijacking em função `SECURITY DEFINER`).
- A primeira instrução do corpo é a checagem de autorização:
  ```sql
  if not exists (select 1 from public.admin_users a where a.user_id = auth.uid()) then
    return;
  end if;
  ```
  `auth.uid()` vem do JWT validado pelo servidor (GoTrue/PostgREST), não é algo que o client possa forjar. Se o usuário autenticado não estiver na tabela `admin_users`, a função **retorna sem executar nenhuma das queries seguintes** — ou seja, a decisão de quem é admin é 100% server-side, baseada em pertencimento a `admin_users`, e acontece *antes* de qualquer leitura de `auth.users`/`expenses`/`categories`/`monthly_balances`.
  - Só depois desse gate a função (via `SECURITY DEFINER`, que bypassa RLS) faz `LEFT JOIN` de `auth.users` com os gastos do mês agregados por usuário — isso explica por que ela consegue listar todo usuário cadastrado mesmo sem lançamento (comentário em `admin.html:339-343`), coisa que uma query comum de um usuário sem privilégio não conseguiria (usuário comum não tem acesso a `auth.users`).
- Em `admin.html:390-411`, a decisão de *mostrar* o painel no client é `isAdmin = !error && rows.length > 0` — client só reage ao que o servidor devolveu; erro, `null` ou array vazio caem todos no mesmo caminho (nega acesso e desloga).

**Verificado — teste dinâmico (comportamento real, não só leitura de código):**
- Login com a conta de teste **A** (recém-criada, não está em `admin_users`) → `sb.rpc('admin_report')` → HTTP 200, corpo `[]`.
- Login com a conta de teste **B** (idem) → mesmo resultado: HTTP 200, `[]`.
- Bate exatamente com o texto da função: nenhuma das duas está em `admin_users`, então o `if not exists (...) return;` barra as duas antes de montar qualquer resultado.

**Conclusão:** confirmado tanto por leitura do código-fonte real da função quanto por teste ao vivo — a autorização de admin é inteiramente server-side, via tabela `admin_users`, sem nenhum caminho client-side que a contorne. Pendência anterior (não ter o texto da função) está resolvida — ver `db_schema_atual.sql`.

---

## (b) Coluna `is_paid` em `expenses`

**Verificado:**
- `migration_5_melhorias.sql` mostra que a única alteração feita foi `ALTER TABLE ... ADD COLUMN is_paid boolean not null default false` — nenhum `ALTER POLICY`, `DROP POLICY` ou `CREATE POLICY` no arquivo. RLS no Postgres atua por **linha**, não por coluna; adicionar uma coluna a uma tabela já protegida por policy de `user_id` não cria brecha por si só, a menos que a policy também tivesse sido tocada — e não foi, pelo menos não nesta migração versionada.
- Teste dinâmico: com a conta A logada, foi inserido um `expense` de teste com `is_paid: true`. Com a conta B (dona de nenhum dado), foram feitas as seguintes tentativas contra a API real:
  - `SELECT` sem filtro em `expenses` → 0 linhas visíveis (o registro de A não aparece).
  - `SELECT` filtrando pelo `id` exato do registro de A → 0 linhas.
  - `UPDATE expenses SET is_paid = false WHERE id = <id de A>` → 200 OK, mas **0 linhas afetadas** (RLS bloqueou silenciosamente, como esperado no Postgres/PostgREST).
  - Confirmado depois, logado como A: o registro segue intacto com `is_paid: true`.

**Conclusão:** isolamento por `user_id` permanece intacto para a coluna `is_paid`, tanto para leitura quanto para escrita, confirmado por teste real contra o banco (não só leitura de código).

---

## (c) Classificação Fixo/Variável (`classificacao`) em `expenses`

**Verificado:** mesmo raciocínio e mesmo teste do item (b), reaproveitando o registro de teste:
- `migration_5_melhorias.sql` só adiciona a coluna `classificacao` (texto) + um `CHECK` de domínio (`'Fixo'` ou `'Variável'` ou nulo) — de novo, nenhuma alteração de policy.
- Teste dinâmico: conta B tentou `UPDATE expenses SET classificacao = 'Variável' WHERE id = <id de A>` → 200 OK, **0 linhas afetadas**. B também não conseguiu ler o valor de `classificacao` do registro de A (já coberto pelo `SELECT` bloqueado do item b, mesma linha/mesma policy).

**Conclusão:** mesma proteção de `user_id` cobre a coluna nova; nenhuma brecha introduzida.

---

## (d) Teste de isolamento clássico (2 contas, 3 páginas)

**Verificado nas policies reais (via API, não só lendo o JS):**

Com a conta A tendo 1 registro em cada uma das 4 tabelas (`categories`, `expenses`, `monthly_balances`, `extra_incomes`) e a conta B sem nenhum dado próprio:

| Tabela | B enxergou algo de A? | Resultado |
|---|---|---|
| `categories` | `SELECT *` sem filtro → 0 linhas | ✅ isolado |
| `expenses` | `SELECT *` sem filtro → 0 linhas; `SELECT` por `id` exato → 0 linhas | ✅ isolado |
| `monthly_balances` | `SELECT *` sem filtro → 0 linhas | ✅ isolado |
| `extra_incomes` | `SELECT *` sem filtro → 0 linhas | ✅ isolado |

E, no sentido inverso, a conta A — mesmo pedindo `SELECT user_id` sem filtro nas 4 tabelas — só recebeu de volta linhas com o próprio `user_id` (0 registros de "outro usuário" em qualquer uma).

**Nas páginas (revisão de código, `index.html` e `historico.html`):** todas as chamadas `sb.from(...)` para `categories`, `expenses`, `monthly_balances` e `extra_incomes` — leitura e escrita — incluem `.eq('user_id', currentUser.id)` (ex.: `index.html:1783-1786`, `historico.html:420-423`). Isso é importante para UX (evita pedir dado que a RLS vai barrar de qualquer forma) mas, como mostrado acima, **a proteção real é a RLS no servidor** — o teste dinâmico confirmou que mesmo ignorando esse filtro do client (chamando a API crua, sem `.eq('user_id', ...)`), nenhum dado de A vazou para B.

**Em `admin.html` (o teste é o oposto — confirmar que só quem é autorizado vê os outros):** já coberto no item (a): as duas contas de teste (não autorizadas) receberam `[]` da RPC, e o client trata isso como "sem acesso" (força logout, mostra "Nenhum dado disponível"). Não foi possível, dentro desta auditoria, testar o caminho positivo (uma conta *autorizada* vendo os dados de todos) porque isso exigiria logar com uma credencial admin real do usuário — fora do escopo de uma auditoria com contas descartáveis.

---

## Limitações desta auditoria

1. ~~Não foi lido o texto SQL de `admin_report()`~~ — **resolvido em 2026-09-16**: texto exato extraído do SQL Editor do Supabase pelo usuário e versionado em [`db_schema_atual.sql`](db_schema_atual.sql). Ver item (a) acima.
2. ~~RLS policies das 4 tabelas não estavam versionadas~~ — **resolvido em 2026-09-16**: as 14 policies (`categories`, `expenses`, `extra_incomes`, `monthly_balances`), incluindo `roles` e `permissive`, também foram extraídas via `pg_policies` e versionadas em `db_schema_atual.sql`.
3. O caminho "positivo" do admin (conta autorizada vendo o relatório de todos) não foi testado nesta sessão — segue como limitação em aberto, fora do escopo de uma auditoria com contas descartáveis.
4. `db_schema_atual.sql` é um snapshot datado (2026-09-16), não uma sincronização automática — se a função ou as policies mudarem no Supabase depois dessa data, o arquivo fica desatualizado até alguém rodar as queries de extração de novo e atualizá-lo manualmente (instruções no topo do próprio arquivo).

## Recomendação

Concluída: `admin_report()` e as `CREATE POLICY` das 4 tabelas agora estão versionadas em [`db_schema_atual.sql`](db_schema_atual.sql), extraídas do estado real do Supabase em 2026-09-16. Qualquer alteração futura nessas regras deve ser refletida ali (rodando de novo as duas queries de extração no topo do arquivo) para que a mudança apareça no `git diff` e continue servindo de registro auditável, em vez de essas regras viverem só dentro do painel do Supabase.

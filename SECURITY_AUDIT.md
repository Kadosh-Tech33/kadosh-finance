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

## Recomendação (auditoria de 2026-09-16)

Concluída: `admin_report()` e as `CREATE POLICY` das 4 tabelas agora estão versionadas em [`db_schema_atual.sql`](db_schema_atual.sql), extraídas do estado real do Supabase em 2026-09-16. Qualquer alteração futura nessas regras deve ser refletida ali (rodando de novo as duas queries de extração no topo do arquivo) para que a mudança apareça no `git diff` e continue servindo de registro auditável, em vez de essas regras viverem só dentro do painel do Supabase.

---
---

# Auditoria de Segurança — 2026-09-23

**Escopo:** (1) força bruta no login, (2) XSS armazenado via texto do usuário, (3) re-confirmação do isolamento RLS.
**Commit base:** `2b4b1e7` (correção de XSS aplicada em cima dele).

Mesma metodologia da auditoria anterior: chamadas diretas à API do Supabase (`/auth/v1`, `/rest/v1`) com a anon key pública, sem passar pelo client JS, mais Playwright (Chromium headless) contra as 3 páginas servidas localmente.

Contas de teste criadas (não excluídas; a anon key não permite): `audit.test.a.1790192665285@kadoshtest.invalid` (`4c5c2d79-e976-4e31-b60a-4666def739e9`) e `audit.test.b.1790192665285@kadoshtest.invalid` (`87c8ab22-a7d0-460e-ae46-6f28a8b93f71`). Todo dado de teste foi removido, **exceto 1 linha em `monthly_balances` da conta A** (mês 2020-01), porque a tabela não tem policy de DELETE (comportamento esperado, ver `db_schema_atual.sql`). Também sobra, de um smoke test anterior no mesmo dia, a conta `smoketest+1790192053971@example.com`.

## (1) Força bruta no login

**Não verificado:** o valor configurado em Authentication → Rate Limits no painel. Não está no repositório, o endpoint público `/auth/v1/settings` não o expõe, e a Management API exige um token pessoal que não existe aqui. **Precisa ser lido no painel pelo dono do projeto.**

**Verificado por teste real** (`POST /auth/v1/token?grant_type=password`, senha errada para o mesmo e-mail, em sequência):

| Medição | Resultado |
|---|---|
| Primeiro 429 (`over_request_rate_limit`) | tentativa #35, após 9,5 s (34 respostas `400 invalid_credentials` antes) |
| Ritmo sustentado (150 s contínuos, 1 req/250 ms) | ~30 tentativas processadas/minuto; o resto recebe 429 |
| Duração do bloqueio após parar | liberado em até 61 s |
| Escopo do bloqueio | **por IP**: durante o bloqueio, a senha *correta* da mesma conta e o login de *outra* conta também receberam 429 |
| Tamanho mínimo de senha no servidor | 6 caracteres (`422 weak_password` com senha `"1"`) |
| Confirmação de e-mail | desligada (`mailer_autoconfirm: true`): qualquer pessoa cria conta sem confirmar o e-mail |

**Avaliação (para decisão, não aplicada):** o rate limit existe e funciona, mas é **por IP e sem bloqueio por conta**. Na prática, ~30 palpites/min ≈ 43 mil/dia por IP, e um atacante com vários IPs multiplica isso linearmente contra o mesmo e-mail. Com senha mínima de 6 caracteres, uma senha fraca/comum cai em horas. Não é adequado **sozinho** para senhas fracas. Opções nativas do Supabase (sem código no client): reduzir o limite de sign-in em Rate Limits; ativar CAPTCHA (Turnstile/hCaptcha) em Auth → Attack Protection; subir o tamanho mínimo e os requisitos de senha; ativar a proteção contra senhas vazadas (HaveIBeenPwned, disponível no plano Pro). Nenhum bloqueio client-side foi implementado, como pedido: não protegeria nada.

## (2) XSS armazenado via texto do usuário

**Pontos encontrados** (texto do banco interpolado sem escape em `innerHTML`):

| Arquivo | Campo | Visto por |
|---|---|---|
| `admin.html` | `categorias[].categoria` (= `categories.nome`, ou `expenses.categoria_id` cru quando não há categoria) | **admin** (texto de qualquer usuário) |
| `admin.html` | `email` | admin |
| `index.html` | nome do card (`categories.nome`), tipo (`categories.tipo`), chip de renda (`extra_incomes.nome`), descrição no modal (`expenses.descricao`), nome no gráfico (lido de `textContent` e reinjetado em `innerHTML`) | o próprio usuário |
| `historico.html` | nome da categoria no detalhamento; descrição no modal (texto e atributo `title`) | o próprio usuário |

**Teste antes da correção:** payloads `<img src=x onerror="alert('TAG')">` com uma TAG única por campo, gravados pela API na conta A (armazenados literalmente, sem nenhuma sanitização no servidor). **Os 8 executaram:** `CAT_NOME` e `RENDA_NOME` no render inicial do index, `DESC_ATUAL` no modal do index, `CAT_NOME` e `DESC_HIST` no histórico, e `CAT_NOME`, `ADMIN_categoria_id` e `ADMIN_EMAIL` no admin.

**Como o admin foi testado:** as contas de teste não são admin (a RPC real devolve `[]`). Para exercitar o código de renderização do painel, a resposta de `/rpc/admin_report` foi interceptada no navegador e substituída por linhas no formato exato da função, com o valor real gravado no banco. O caminho de dados até ali é direto: `admin_report()` repassa `c.nome`/`e.categoria_id` sem transformação, e é `SECURITY DEFINER`, então lê dados de todos. Um usuário comum só precisa renomear a própria categoria para atingir a sessão do admin. O caminho com uma conta admin real não foi testado.

**E-mail como vetor:** o cadastro com HTML no e-mail foi recusado pelo Supabase Auth (`400 validation_failed`, 2 variações). O escape foi aplicado mesmo assim, como defesa extra.

**Correção:** `escapeHtml()` (escapa `& < > " '`) em cada um dos 3 arquivos, aplicado em todos os pontos acima. O `textContent` já usado em outros lugares foi mantido.

**Teste depois da correção:** mesmo roteiro e mesmos payloads. **Nenhum executou** nas 3 páginas, e o texto aparece literalmente (`<img src=x ...>` visível como texto) em todos os pontos. A varredura final por `${...}` com nome/descrição/e-mail/tipo sem escape só encontrou constantes do código.

**Não coberto:** `category_key` controlado pelo usuário entra em seletores CSS (`.expense-card[data-id="..."]`). Um valor com aspas quebra o seletor, o que afeta só a página do próprio usuário. Não é XSS e não foi alterado.

## (3) Isolamento RLS: sem regressão

Conta A com 1 registro em cada uma das 4 tabelas; conta B sem dados. **36/36 checks passaram:**

- B, nas 4 tabelas: `SELECT *` sem filtro → 0 linhas; `SELECT` pelo registro exato de A → 0; `UPDATE` → 0 afetadas; `DELETE` → 0 afetadas. Registro de A intacto depois.
- Sem login (só anon key): 0 linhas nas 4 tabelas.
- A, `SELECT user_id` sem filtro: só linhas próprias nas 4 tabelas.
- **Novo:** B tentou plantar dado na conta de A (`INSERT` com `user_id = A` em `categories` e `extra_incomes`; `UPDATE` do `user_id` da própria linha para A em `categories` e `expenses`) → todos `403 / 42501`. Ou seja, um usuário não consegue injetar payload XSS na conta de outro, e o único alvo cruzado real é o admin (item 2).
- `admin_report` como A, como B e sem login → `200 []`.

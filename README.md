# Plano de Ação 5W1H — Gestão de Terceiros (bp bioenergy)

App estático (`index.html`) + Supabase (banco, storage de evidências e Edge Function `api`).

- `index.html` — aplicativo; todo acesso a dados passa pela Edge Function `api`.
- `supabase/schema.sql` — tabelas (RLS ligado, sem policies: a anon key não lê nada direto) e bucket privado `evidencias`.
- `supabase/functions/api/index.ts` — login por código, listagens, criação de ações, evidências e conclusão (admin).

Os dados (fornecedores, ações, códigos de acesso) ficam somente no Supabase e não são versionados aqui.

-- Schema do app Plano de Ação 5W1H (Supabase / Postgres)
-- Execute no SQL Editor do projeto. Acesso ao banco é feito SOMENTE pela Edge Function "api".
create extension if not exists pgcrypto;

create table if not exists public.suppliers (
  supplier_code text primary key,
  razao_social  text not null,
  cnpj text, cluster text, area text, analista text, contato text, fone text, email text,
  created_at timestamptz not null default now()
);

create table if not exists public.access_codes (
  code          text primary key,
  role          text not null check (role in ('supplier','admin')),
  supplier_code text references public.suppliers(supplier_code) on delete cascade,
  active        boolean not null default true,
  created_at    timestamptz not null default now(),
  constraint supplier_code_required_for_role check ((role = 'supplier' and supplier_code is not null) or (role = 'admin'))
);

create table if not exists public.actions (
  id bigint generated always as identity primary key,
  supplier_code text not null references public.suppliers(supplier_code) on delete cascade,
  origem_arquivo text, unidade text, fase text,
  status text not null default 'em_andamento'
    check (status in ('em_andamento','atrasada','concluida','cancelada','para_informacao')),
  data_reuniao date, assunto text, descricao text, responsavel text, previsao_texto text, data_conclusao date,
  what_o_que text, who_quem text, when_quando date, where_onde text, why_por_que text, how_como text,
  evidencia_path text, evidencia_nome text, evidencia_enviada_em timestamptz,
  concluida_por_code text, concluida_em timestamptz, created_by_code text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists idx_actions_supplier_code on public.actions(supplier_code);
create index if not exists idx_actions_status on public.actions(status);

create or replace function public.set_updated_at() returns trigger language plpgsql set search_path = public
as $$ begin new.updated_at = now(); return new; end; $$;
drop trigger if exists trg_actions_updated_at on public.actions;
create trigger trg_actions_updated_at before update on public.actions for each row execute function public.set_updated_at();

-- RLS ligado e SEM policies: a anon key não lê nem grava nada direto.
alter table public.suppliers enable row level security;
alter table public.actions enable row level security;
alter table public.access_codes enable row level security;
revoke all on public.suppliers, public.actions, public.access_codes from anon, authenticated;

insert into storage.buckets (id, name, public) values ('evidencias', 'evidencias', false) on conflict (id) do nothing;

-- v2: numeração de itens por fornecedor e observações das ações
alter table public.actions add column if not exists item integer;
create index if not exists idx_actions_data_reuniao on public.actions(data_reuniao);
create table if not exists public.action_notes (
  id bigint generated always as identity primary key,
  action_id bigint not null references public.actions(id) on delete cascade,
  author_role text not null,
  author_name text,
  note text not null,
  created_at timestamptz not null default now()
);
create index if not exists idx_action_notes_action on public.action_notes(action_id);
alter table public.action_notes enable row level security;
revoke all on public.action_notes from anon, authenticated;

-- SIGA ALQIA 3.0 — cadastro de contas por nível e trilha de auditoria
-- Executar uma única vez após 001-004 e apurações/POS.
-- 'papel' é uma chave de compatibilidade com o painel/RLS existente.
begin;

alter table public.profiles
  add column if not exists nivel_acesso text not null default 'auditor';

update public.profiles
set nivel_acesso = case
  when papel = 'auditor' then 'auditor'
  when lower(funcao) like '%admin%' then 'administrador'
  when lower(funcao) like '%lider%' or lower(funcao) like '%líder%' then 'lider'
  else 'supervisor'
end;

alter table public.profiles
  add constraint profiles_nivel_acesso_valid
  check (nivel_acesso in ('auditor','lider','supervisor','administrador'));

alter table public.profiles
  add constraint profiles_nivel_papel_consistente
  check (
    (nivel_acesso = 'auditor' and papel = 'auditor')
    or (nivel_acesso in ('lider','supervisor','administrador') and papel = 'coordenador')
  );

create or replace function private.can_create_accounts()
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid())
      and papel = 'coordenador'
      and nivel_acesso in ('lider','supervisor','administrador')
  );
$$;
revoke all on function private.can_create_accounts() from public, anon;
grant execute on function private.can_create_accounts() to authenticated;

create table if not exists public.auditoria_acessos (
  id uuid primary key default gen_random_uuid(),
  criador_id uuid not null references public.profiles(id),
  usuario_criado_id uuid references public.profiles(id) on delete set null,
  email text not null,
  nivel_acesso text not null
    check (nivel_acesso in ('auditor','lider','supervisor','administrador')),
  funcao text not null,
  criado_em timestamptz not null default now()
);
create index if not exists auditoria_acessos_criado_em_idx
  on public.auditoria_acessos(criado_em desc);

revoke all on public.auditoria_acessos from public, anon, authenticated;
grant select on public.auditoria_acessos to authenticated;
alter table public.auditoria_acessos enable row level security;
create policy auditoria_acessos_read_management
  on public.auditoria_acessos for select to authenticated
  using ((select private.can_create_accounts()));

commit;

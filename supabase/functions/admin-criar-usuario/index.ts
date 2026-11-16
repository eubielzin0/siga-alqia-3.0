import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = new Set([
  "https://siga-alqia-bnm-teste.vercel.app",
  "https://siga-alqia-bnm-teste-eubielzin0-8413.vercel.app",
]);

const TITLES: Record<string, string[]> = {
  auditor: ["Auditor", "Auditor de Coleta", "Auditor de Fechamento"],
  lider: ["Líder de Auditoria"],
  supervisor: ["Supervisor", "Supervisora"],
  administrador: ["Administrador", "Administradora"],
};

const PRIVILEGED = new Set(["lider", "supervisor", "administrador"]);
const MANAGERS = new Set(["supervisor", "administrador"]);

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("origin");
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return new Response("Origem não autorizada.", { status: 403 });
  }
  const headers = {
    "Access-Control-Allow-Origin": origin || "https://siga-alqia-bnm-teste.vercel.app",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-api-version",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    Vary: "Origin",
  };
  const reply = (status: number, data: Record<string, unknown>) =>
    new Response(JSON.stringify(data), { status, headers });

  if (req.method === "OPTIONS") return new Response("ok", { headers });
  if (req.method !== "POST") return reply(405, { error: "Método não permitido." });

  const authorization = req.headers.get("authorization") || "";
  if (!/^Bearer\s+\S+$/i.test(authorization)) {
    return reply(401, { error: "Faça login para criar usuários." });
  }

  const url = Deno.env.get("SUPABASE_URL");
  const secret = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !secret) return reply(503, { error: "Configuração segura indisponível." });

  // A chave administrativa permanece APENAS no ambiente seguro do Supabase.
  const admin = createClient(url, secret, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  try {
    const token = authorization.replace(/^Bearer\s+/i, "");
    const { data: session, error: authError } = await admin.auth.getUser(token);
    if (authError || !session?.user) {
      return reply(401, { error: "Sua sessão expirou. Entre novamente." });
    }

    // A autorização vem do banco, jamais do cargo informado pelo navegador.
    const { data: caller, error: profileError } = await admin.from("profiles")
      .select("papel,nivel_acesso").eq("id", session.user.id).single();
    if (profileError || !caller || caller.papel !== "coordenador" || !PRIVILEGED.has(caller.nivel_acesso)) {
      return reply(403, { error: "Você não possui permissão para criar acessos." });
    }

    let input: Record<string, unknown>;
    try { input = await req.json(); }
    catch { return reply(400, { error: "Preencha os dados de cadastro." }); }

    const nome = String(input.nome || "").trim().replace(/\s+/g, " ");
    const email = String(input.email || "").trim().toLowerCase();
    const nivel = String(input.nivel_acesso || "");
    const funcao = String(input.funcao || "");
    const senha = String(input.senha || "");
    if (nome.length < 3 || nome.length > 90 || !/^[\p{L}\p{M}\s.'-]+$/u.test(nome)) {
      return reply(400, { error: "Informe o nome completo do colaborador (sem caracteres especiais inválidos)." });
    }
    if (!/^[a-z][a-z0-9._-]{2,80}@bossanovamall\.com$/.test(email)) {
      return reply(400, { error: "Use um e-mail corporativo @bossanovamall.com." });
    }
    if (!Object.prototype.hasOwnProperty.call(TITLES, nivel) || !TITLES[nivel].includes(funcao)) {
      return reply(400, { error: "Perfil de acesso ou função inválidos." });
    }
    if (!MANAGERS.has(caller.nivel_acesso) && nivel !== "auditor") {
      return reply(403, { error: "Líderes podem cadastrar somente auditores." });
    }
    if (senha.length < 16 || senha.length > 100 ||
        !/[A-Z]/.test(senha) || !/[a-z]/.test(senha) ||
        !/[0-9]/.test(senha) || !/[^A-Za-z0-9]/.test(senha)) {
      return reply(400, { error: "A senha exige ao menos 16 caracteres, letras maiúsculas e minúsculas, números e símbolos." });
    }

    const papel = nivel === "auditor" ? "auditor" : "coordenador";
    const { data: created, error: creationError } = await admin.auth.admin.createUser({
      email, password: senha, email_confirm: true,
      user_metadata: { nome, funcao },
    });
    if (creationError || !created?.user) {
      return reply(409, { error: "Não foi possível criar o acesso. Confira se o e-mail já possui uma conta." });
    }

    // Assegurar perfil, nível e trilha de auditoria antes de confirmar a criação.
    const uid = created.user.id;
    try {
      const { data: profile, error: saveError } = await admin.from("profiles")
        .upsert({ id: uid, nome, funcao, papel, nivel_acesso: nivel }, { onConflict: "id" })
        .select("id,papel,nivel_acesso").single();
      if (saveError || profile?.papel !== papel || profile.nivel_acesso !== nivel) {
        throw new Error("Não foi possível definir as permissões.");
      }
      const { error: auditError } = await admin.from("auditoria_acessos").insert({
        criador_id: session.user.id, usuario_criado_id: uid,
        email, nivel_acesso: nivel, funcao,
      });
      if (auditError) throw new Error("Não foi possível registrar a operação de cadastro.");
    } catch (_error) {
      // Uma falha não deixa uma conta parcialmente autorizada disponível.
      const { error: rollbackError } = await admin.auth.admin.deleteUser(uid);
      if (rollbackError) console.error("Falha ao reverter cadastro incompleto.");
      return reply(500, { error: "A configuração do usuário falhou. Confira a lista de usuários antes de tentar novamente." });
    }

    return reply(201, { ok: true, email, nome, funcao, papel, nivel_acesso: nivel });
  } catch (error) {
    console.error("admin-criar-usuario:", error instanceof Error ? error.message : "erro inesperado");
    return reply(500, { error: "Falha temporária. Tente novamente." });
  }
});

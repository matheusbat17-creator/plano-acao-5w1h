import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const db = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });
class HttpError extends Error { constructor(public status: number, msg: string) { super(msg); } }

/* ---------- sessão: token HMAC assinado (12h) ---------- */
const enc = new TextEncoder();
const b64u = (buf: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const hmacKey = () => crypto.subtle.importKey("raw", enc.encode("pa5w1h:" + SERVICE_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

async function signToken(p: { role: string; sc: string | null }) {
  const payload = b64u(enc.encode(JSON.stringify({ ...p, exp: Date.now() + 12 * 3600 * 1000 })));
  const sig = b64u(await crypto.subtle.sign("HMAC", await hmacKey(), enc.encode(payload)));
  return `${payload}.${sig}`;
}
async function verifyToken(token?: string): Promise<{ role: string; sc: string | null }> {
  if (!token || !token.includes(".")) throw new HttpError(401, "Sessão inválida.");
  const [payload, sig] = token.split(".");
  const ok = await crypto.subtle.verify("HMAC", await hmacKey(), fromB64u(sig), enc.encode(payload));
  if (!ok) throw new HttpError(401, "Sessão inválida.");
  const p = JSON.parse(new TextDecoder().decode(fromB64u(payload)));
  if (!p.exp || p.exp < Date.now()) throw new HttpError(401, "Sessão expirada. Faça login novamente.");
  return p;
}

const OPEN = ["em_andamento", "atrasada", "para_informacao"];
const HAS_CONTENT = "assunto.not.is.null,what_o_que.not.is.null,descricao.not.is.null"; // ignora linhas vazias importadas

const esc = (s: string) => s.replace(/[%,()*\\]/g, " ");

function scopeSupplier(s: { role: string; sc: string | null }, requested?: string) {
  if (s.role === "admin") return requested || null;
  return s.sc;
}

async function getOwnedAction(s: { role: string; sc: string | null }, id: number) {
  const { data, error } = await db.from("actions").select("*").eq("id", id).maybeSingle();
  if (error) throw new HttpError(500, error.message);
  if (!data) throw new HttpError(404, "Ação não encontrada.");
  if (s.role !== "admin" && data.supplier_code !== s.sc) throw new HttpError(403, "Sem permissão para esta ação.");
  return data;
}

async function handle(req: Request) {
  const body = await req.json().catch(() => ({}));
  const op = body.op as string;

  if (op === "login") {
    const code = String(body.code ?? "").trim();
    if (!code) throw new HttpError(400, "Informe o código.");
    const { data: ac } = await db.from("access_codes").select("role, supplier_code, active").eq("code", code).maybeSingle();
    if (!ac || !ac.active) throw new HttpError(401, "Código inválido.");
    let razao: string | null = null;
    if (ac.supplier_code) {
      const { data: sp } = await db.from("suppliers").select("razao_social").eq("supplier_code", ac.supplier_code).maybeSingle();
      razao = sp?.razao_social ?? null;
    }
    return { token: await signToken({ role: ac.role, sc: ac.supplier_code }), app_role: ac.role, supplier_code: ac.supplier_code, razao_social: razao };
  }

  const s = await verifyToken(body.token);

  switch (op) {
    case "suppliers": {
      if (s.role !== "admin") throw new HttpError(403, "Somente administrador.");
      const { data, error } = await db.from("suppliers").select("supplier_code, razao_social").order("razao_social");
      if (error) throw new HttpError(500, error.message);
      return { data };
    }

    case "counts": {
      const sc = scopeSupplier(s, body.supplier);
      let q = db.from("actions").select("status").or(HAS_CONTENT);
      if (sc) q = q.eq("supplier_code", sc);
      const { data, error } = await q.limit(10000);
      if (error) throw new HttpError(500, error.message);
      const counts: Record<string, number> = { em_andamento: 0, atrasada: 0, concluida: 0, cancelada: 0, para_informacao: 0 };
      (data ?? []).forEach((r: any) => { if (r.status in counts) counts[r.status]++; });
      return { counts };
    }

    case "list_open": {
      const sc = scopeSupplier(s, body.supplier);
      let q = db.from("actions").select("*").in("status", OPEN).or(HAS_CONTENT).order("created_at", { ascending: false }).order("id", { ascending: false }).limit(2000);
      if (sc) q = q.eq("supplier_code", sc);
      const search = esc(String(body.search ?? "").trim());
      if (search) q = q.or(`assunto.ilike.%${search}%,responsavel.ilike.%${search}%,descricao.ilike.%${search}%,what_o_que.ilike.%${search}%`);
      const { data, error } = await q;
      if (error) throw new HttpError(500, error.message);
      return { data };
    }

    case "list_history": {
      if (s.role !== "admin") throw new HttpError(403, "Somente administrador.");
      const page = Math.max(0, Number(body.page) || 0), size = 25;
      let q = db.from("actions").select("*", { count: "exact" })
        .in("status", body.status ? [body.status] : ["concluida", "cancelada"])
        .order("concluida_em", { ascending: false, nullsFirst: false }).order("id", { ascending: false })
        .range(page * size, page * size + size - 1);
      if (body.supplier) q = q.eq("supplier_code", body.supplier);
      const search = esc(String(body.search ?? "").trim());
      if (search) q = q.or(`assunto.ilike.%${search}%,responsavel.ilike.%${search}%,what_o_que.ilike.%${search}%`);
      const { data, error, count } = await q;
      if (error) throw new HttpError(500, error.message);
      return { data, count };
    }

    case "create_action": {
      const f = body.fields ?? {};
      const sc = s.role === "admin" ? body.supplier : s.sc;
      if (!sc) throw new HttpError(400, "Fornecedor não informado.");
      const what = String(f.what ?? "").trim(), why = String(f.why ?? "").trim(), who = String(f.who ?? "").trim();
      const when = String(f.when ?? "").trim();
      if (!what || !why || !who || !/^\d{4}-\d{2}-\d{2}$/.test(when)) throw new HttpError(400, "Preencha O quê, Por quê, Quem e Quando.");
      const how = String(f.how ?? "").trim(), where = String(f.where ?? "").trim();
      const { data, error } = await db.from("actions").insert({
        supplier_code: sc, origem_arquivo: null, status: "em_andamento",
        what_o_que: what, why_por_que: why, how_como: how, who_quem: who, where_onde: where, when_quando: when,
        assunto: what, descricao: how, responsavel: who, unidade: where, fase: why,
        created_by_code: s.sc || "admin",
      }).select().single();
      if (error) throw new HttpError(400, error.message);
      return { data };
    }

    case "evidence_upload_url": {
      const a = await getOwnedAction(s, Number(body.action_id));
      if (s.role !== "admin" && a.status === "concluida") throw new HttpError(403, "Ação já concluída.");
      const safe = String(body.filename ?? "arquivo").normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^\w.\-]+/g, "_").slice(-100);
      const path = `${a.supplier_code}/${a.id}/${Date.now()}_${safe}`;
      const { data, error } = await db.storage.from("evidencias").createSignedUploadUrl(path);
      if (error) throw new HttpError(500, error.message);
      return { path, token: data.token };
    }

    case "evidence_register": {
      const a = await getOwnedAction(s, Number(body.action_id));
      const path = String(body.path ?? "");
      if (!path.startsWith(`${a.supplier_code}/${a.id}/`)) throw new HttpError(400, "Caminho inválido.");
      const { error } = await db.from("actions").update({
        evidencia_path: path, evidencia_nome: String(body.nome ?? "").slice(0, 200), evidencia_enviada_em: new Date().toISOString(),
      }).eq("id", a.id);
      if (error) throw new HttpError(500, error.message);
      return { ok: true };
    }

    case "evidence_url": {
      const path = String(body.path ?? "");
      const sc = path.split("/")[0];
      if (s.role !== "admin" && sc !== s.sc) throw new HttpError(403, "Sem permissão.");
      const { data, error } = await db.storage.from("evidencias").createSignedUrl(path, 120);
      if (error) throw new HttpError(404, "Arquivo não encontrado.");
      return { url: data.signedUrl };
    }

    case "conclude": {
      if (s.role !== "admin") throw new HttpError(403, "Somente o analista (admin) pode concluir.");
      const a = await getOwnedAction(s, Number(body.action_id));
      const { error } = await db.from("actions").update({
        status: "concluida", data_conclusao: new Date().toISOString().slice(0, 10),
        concluida_por_code: "admin", concluida_em: new Date().toISOString(),
      }).eq("id", a.id);
      if (error) throw new HttpError(500, error.message);
      return { ok: true };
    }

    default:
      throw new HttpError(400, "Operação desconhecida.");
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  try {
    return json(await handle(req));
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: "Erro interno." }, 500);
  }
});

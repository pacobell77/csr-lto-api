import { load as yamlLoad } from "js-yaml";

function send(res: any, status: number, body: any) {
  res
    .status(status)
    .setHeader("content-type", "application/json; charset=utf-8")
    .send(JSON.stringify(body));
}

export default async function handler(req: any, res: any) {
  try {
    const path = (req.query?.path as string) || "allowlist"; // "allowlist" | "offers"
    const key  = (req.query?.key as string) || "";
    const fileParam = (req.query?.filename as string) || ""; // optional override

    // Serve YAML from /public (static file)
    const host = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "http://localhost:3000";
    const yamlFile = fileParam || "csr_lto_2025_08_final_v4.yaml";
    const yamlUrl = `${host}/${yamlFile}`;

    const r = await fetch(yamlUrl, { cache: "no-store" });
    if (!r.ok) return send(res, 502, { error: "fetch_failed", status: r.status, yamlUrl });

    const text = await r.text();
    const data: any = yamlLoad(text);

    const ns = data?.LTO_v2025_08;
    if (!ns) return send(res, 422, { error: "namespace_missing", detail: "LTO_v2025_08 not found" });

    const allow = ns.allow_only_these_keys || ns.manifest?.allow_only_these_keys;
    if (!Array.isArray(allow)) {
      return send(res, 422, { error: "allowlist_missing", detail: "allow_only_these_keys not found at top-level or in manifest" });
    }

    const safeOffer = (k: string) => {
      const raw = ns[k] || {};
      return {
        key: k,
        summary: raw.summary ?? null,
        expiration: raw.expiration ?? null
      };
    };

    if (path === "allowlist") {
      return send(res, 200, {
        source_file: yamlFile,
        namespace: "LTO_v2025_08",
        file_id: ns.file_id ?? ns.manifest?.file_id ?? null,
        allow_only_these_keys: allow
      });
    }

    if (path === "offers") {
      if (key) {
        if (!allow.includes(key)) return send(res, 403, { error: "non_allowlisted_key", key });
        return send(res, 200, { source_file: yamlFile, namespace: "LTO_v2025_08", offer: safeOffer(key) });
      }
      return send(res, 200, { source_file: yamlFile, namespace: "LTO_v2025_08", offers: allow.map(safeOffer) });
    }

    return send(res, 400, { error: "unknown_path", hint: "use ?path=allowlist or ?path=offers" });
  } catch (e: any) {
    return send(res, 500, { error: "server_error", detail: String(e?.message ?? e) });
  }
}

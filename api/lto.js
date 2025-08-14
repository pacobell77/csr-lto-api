const { load: yamlLoad } = require("js-yaml");

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

module.exports = async (req, res) => {
    try {
    // --- TOKEN GUARD -------------------------------------------------------
    const requiredToken = process.env.LTO_API_TOKEN;
    const authHeader = (req.headers && req.headers.authorization) || "";
    const provided = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : "";
    if (requiredToken && provided !== requiredToken) {
      return send(res, 401, { error: "unauthorized", hint: "missing_or_bad_token" });
    }
    // ----------------------------------------------------------------------
  
    const path = (req.query && req.query.path) || "allowlist"; // "allowlist" | "offers"
    const key = (req.query && req.query.key) || "";
    const fileParam = (req.query && req.query.filename) || "";

    // Build URL to the static YAML served from /public
    const proto = req.headers["x-forwarded-proto"] || "https";
    const hostHeader = req.headers["x-forwarded-host"] || req.headers["host"];
    const yamlFile = fileParam || "csr_lto_2025_08_final_v4.yaml"; // underscores version
    const yamlUrl = `${proto}://${hostHeader}/${yamlFile}`;

    const r = await fetch(yamlUrl, { cache: "no-store" });
    if (!r.ok) return send(res, 502, { error: "fetch_failed", status: r.status, yamlUrl });

    const text = await r.text();
    let data;
    try {
      data = yamlLoad(text);
    } catch (err) {
      return send(res, 422, { error: "yaml_parse_error", detail: String(err && err.message ? err.message : err) });
    }

    const ns = data && data.LTO_v2025_08;
    if (!ns) return send(res, 422, { error: "namespace_missing", detail: "LTO_v2025_08 not found" });

    const allow = ns.allow_only_these_keys || (ns.manifest && ns.manifest.allow_only_these_keys);
    if (!Array.isArray(allow)) {
      return send(res, 422, { error: "allowlist_missing", detail: "allow_only_these_keys not found at top-level or in manifest" });
    }

    const toArray = (v) => Array.isArray(v) ? v : (v ? [String(v)] : []);
    const safeOffer = (k) => {
      const raw = ns[k] || {};
      return {
        key: k,
        summary: raw.summary ?? null,
        expiration: raw.expiration ?? null,
        official_domains: toArray(raw.official_domains),
        terms_urls: toArray(raw.terms_urls),
        enrollment_urls: toArray(raw.enrollment_urls)
      };
    };

    if (path === "allowlist") {
      return send(res, 200, {
        source_file: yamlFile,
        namespace: "LTO_v2025_08",
        file_id: ns.file_id || (ns.manifest && ns.manifest.file_id) || null,
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
  } catch (e) {
    console.error("LTO_API_ERROR", e);
    return send(res, 500, { error: "server_error", detail: String(e && e.message ? e.message : e) });
  }
};

// Minimal status badge seed. Usage:
// <script src="https://beanstalkdev.netlify.app/seeds/status.js"
//   data-beanstalk-owner="OWNER"
//   data-beanstalk-repo="REPO"
//   data-path="pods/status/content/status.json"
//   data-target="beanstalk-status"
//   defer></script>
// <div id="beanstalk-status"></div>

(function () {
  function attrs(s){ return { owner: s.dataset.beanstalkOwner, repo: s.dataset.beanstalkRepo, path: s.dataset.path, target: s.dataset.target||"beanstalk-status", ref: s.dataset.ref }; }
  function el(tag, opts){ const n=document.createElement(tag); if(opts){ Object.assign(n, opts); if(opts.className) n.className=opts.className; } return n; }
  function fmt(ts){ try{ return new Date(ts).toLocaleString(); }catch{ return ts; } }

  const s = document.currentScript;
  const { owner, repo, path, target, ref } = attrs(s);
  if(!owner || !repo){ console.warn("[beanstalk] status seed missing owner/repo"); return; }

  const mount = document.getElementById(target) || (function(){ const d = el("div",{id:target}); document.body.appendChild(d); return d; })();

  const base = (s.src || "").split("/seeds/")[0];
  const u = new URL(base + "/.netlify/functions/seeds");
  u.searchParams.set("owner", owner);
  u.searchParams.set("repo", repo);
  if (path) u.searchParams.set("path", path);
  if (ref) u.searchParams.set("ref", ref);
  if (s.dataset.dev === "1") {
    u.searchParams.set("v", String(Date.now()));
  }

  fetch(u.toString(), { mode: "cors" })
    .then(r => r.json())
    .then(j => {
      let status = j?.json?.status || "unknown";
      let updated = j?.json?.updated || null;

      const wrap = el("div", { className: "bs-status" });
      const badge = el("span", { className: "bs-badge" });
      const cls = status === "operational" ? "ok" : status === "degraded" ? "degraded" : status === "down" ? "down" : "unknown";
      badge.className = `bs-badge ${cls}`;
      badge.textContent = cls === "ok" ? "● Operational" : cls === "degraded" ? "● Degraded" : cls === "down" ? "● Down" : "● Unknown";
      wrap.appendChild(badge);

      const meta = el("div", { className: "bs-meta" });
      meta.textContent = updated ? `Updated ${fmt(updated)}` : "";
      wrap.appendChild(meta);

      const style = el("style");
      style.textContent = `
        .bs-status{display:inline-flex;align-items:center;gap:10px;padding:8px 12px;border-radius:12px;border:1px solid #e5e7eb;background:rgba(255,255,255,.6);backdrop-filter:saturate(1.8) blur(4px);font:14px/1.3 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
        .bs-badge{font-weight:600}
        .bs-meta{color:#666;font-size:12px}
        .bs-badge::before{content:"";display:inline-block;width:.6em;height:.6em;border-radius:50%;margin-right:.35em;background:#999;vertical-align:middle}
        .bs-badge.ok::before{background:#119d59}
        .bs-badge.degraded::before{background:#b68b00}
        .bs-badge.down::before{background:#d14343}
      `;
      mount.innerHTML = "";
      mount.appendChild(style);
      mount.appendChild(wrap);
    })
    .catch(e => {
      mount.textContent = "Status unavailable";
      console.warn("[beanstalk] status seed error", e);
    });
})();
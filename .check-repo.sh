set -e
echo "→ Checking required directories…"
req_dirs=(site netlify/functions admin cloud/app cloud/admin cloud/data shared/styles shared/ui pods)
missing=0
for d in "${req_dirs[@]}"; do
  [ -d "$d" ] || { echo "MISSING DIR  : $d"; missing=1; }
done

echo "→ Checking required files…"
req_files=(netlify.toml site/index.html netlify/functions/health.js netlify/functions/github.js netlify/functions/oauth.js netlify/functions/envcheck.js)
for f in "${req_files[@]}"; do
  [ -f "$f" ] || { echo "MISSING FILE : $f"; missing=1; }
done

echo "→ Validating netlify.toml…"
grep -q 'publish = "site"' netlify.toml  || { echo 'netlify.toml: missing publish = "site"'; missing=1; }
grep -q 'functions = "netlify/functions"' netlify.toml || { echo 'netlify.toml: missing functions = "netlify/functions"'; missing=1; }

echo
if [ "$missing" -eq 0 ]; then
  echo "✅ All required items present."
else
  echo "❌ Missing items found (see above)."
fi

echo
echo "→ Tree (depth 2):"
find . -maxdepth 2 -type d \( -name .git -o -name node_modules \) -prune -o -print | sed -n '1,200p'

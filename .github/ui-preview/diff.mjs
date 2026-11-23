// Builds a unified diff for a PR from the files API, since the diff endpoint
// refuses PRs that touch more than 300 files. Each file's patch is written
// back in the shape record.mjs's codeContext expects (diff --git / --- / +++
// / @@ hunks). Files whose patch the API omits (over ~3000 changed lines,
// or binary) are left with a header only.
//
// env: GITHUB_TOKEN, GITHUB_REPOSITORY, PR
import fs from "node:fs";

const repo = process.env.GITHUB_REPOSITORY;
const pr = Number(process.env.PR);
const token = process.env.GITHUB_TOKEN;

async function gh(p) {
  const headers = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`https://api.github.com${p}`, { headers });
  if (!res.ok) throw new Error(`GET ${p}: ${res.status} ${(await res.text()).slice(0, 300)}`);
  return res.json();
}

const out = [];
for (let page = 1; page <= 30; page++) {
  const batch = await gh(`/repos/${repo}/pulls/${pr}/files?per_page=100&page=${page}`);
  for (const f of batch) {
    const name = f.filename;
    out.push(`diff --git a/${name} b/${name}`);
    if (f.status === "added") out.push(`--- /dev/null\n+++ b/${name}`);
    else if (f.status === "removed") out.push(`--- a/${name}\n+++ /dev/null`);
    else out.push(`--- a/${name}\n+++ b/${name}`);
    if (f.patch) out.push(f.patch.replace(/\n?$/, ""));
    else out.push(`@@ file changed, patch not returned by the API (${f.status}) @@`);
  }
  if (batch.length < 100) break;
}
fs.writeSync(1, out.join("\n") + "\n");

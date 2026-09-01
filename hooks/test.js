#!/usr/bin/env node
// Self-check: bad fixtures must trigger, good fixtures must stay silent.
// Also tests findings tracking and the report. Run: node hooks/test.js
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const DIR = path.resolve(__dirname, '..');
const SCAN = path.join(DIR, 'hooks', 'scan.js');
const REPORT = path.join(DIR, 'hooks', 'report.js');
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-test-'));

let pass = 0, fail = 0;
const seen = new Set();

function runScan(file) {
  const payload = JSON.stringify({ tool_input: { file_path: file } });
  const r = spawnSync('node', [SCAN], {
    input: payload,
    env: { ...process.env, SECURE_CODING_STATE: path.join(TMP, 'findings.jsonl'), SECURE_CODING_REPORT: 'off' },
    encoding: 'utf8',
  });
  return r.stdout || '';
}

function uniq(name) {
  if (seen.has(name)) { console.error(`DUPLICATE FIXTURE NAME: ${name}`); process.exit(2); }
  seen.add(name);
}

function bad(name, ext, content, expectedId) {
  uniq(name);
  const file = path.join(TMP, `${name}.${ext}`);
  fs.writeFileSync(file, content);
  const out = runScan(file);
  if (out.includes(`## ${expectedId}`)) pass++;
  else { fail++; console.log(`MISS  ${name} (want ${expectedId})`); }
}

function good(name, ext, content) {
  uniq(name);
  const file = path.join(TMP, `${name}.${ext}`);
  fs.writeFileSync(file, content);
  const out = runScan(file);
  if (out.trim() === '') pass++;
  else { fail++; console.log(`FALSE+ ${name}`); }
}

// --- original languages ---
bad('md5', 'py', 'h = hashlib.md5(data)', 'weak-hash');
bad('pwhash', 'py', 'd = hashlib.sha256(password)', 'pw-fast-hash');
bad('pickle', 'py', 'obj = pickle.loads(body)', 'insecure-deserialization');
bad('yaml', 'py', 'cfg = yaml.load(text)', 'insecure-deserialization');
bad('verify', 'py', 'requests.get(u, verify=False)', 'tls-off');
bad('tlsjs', 'js', 'https.get({rejectUnauthorized: false})', 'tls-off');
bad('inner', 'js', 'el.innerHTML = userInput', 'xss-sink');
bad('react', 'jsx', 'return <div dangerouslySetInnerHTML={h} />', 'xss-sink');
bad('ev', 'js', 'eval(req.query.q)', 'eval');
bad('sqlf', 'py', 'cur.execute(f"SELECT * FROM t WHERE i={i}")', 'sql-concat');
bad('sqltpl', 'js', 'db.query(`SELECT * FROM t WHERE i=${id}`)', 'sql-concat');
// JS string-concat SQL: inline in the call, and built into a variable first.
bad('sqlJsInline', 'js', 'db.query("SELECT * FROM t WHERE a=\'" + a + "\'")', 'sql-concat');
bad('sqlJsVar', 'js', 'const q = "SELECT * FROM t WHERE a=" + a;', 'sql-concat');
bad('sqlJsLet', 'js', 'let sql = "UPDATE users SET n=" + n + " WHERE id=" + id;', 'sql-concat');
bad('sqlJsAppend', 'js', 's += " WHERE a=" + a;', 'sql-concat');
// A SQL keyword inside ordinary prose is not a query.
good('sqlProseNotQuery', 'js', 'const msg = "Please UPDATE your profile " + name;');
good('sqlParamOk', 'js', 'db.query("SELECT * FROM t WHERE a = ?", [a]);');
bad('sh', 'py', 'subprocess.run(cmd, shell=True)', 'shell');
bad('rng', 'js', 'const token = Math.random().toString(36)', 'weak-rng');
bad('apikey', 'py', 'api_key = "sk-abc123def456ghi789xyz"', 'secret');
bad('ecb', 'py', 'AES.new(k, AES.MODE_ECB)', 'weak-crypto');
bad('ck', 'js', 'res.cookie("sid", v, {httpOnly: false})', 'cookie');
bad('jwtnone', 'js', 'jwt.verify(t, k, {algorithms: ["none"]})', 'jwt');
bad('strcpy', 'c', 'strcpy(buf, argv[1]);', 'mem');
bad('corsw', 'js', 'res.set("Access-Control-Allow-Origin", "*")', 'cors');
bad('csrfx', 'py', '@csrf_exempt\ndef login(request):', 'csrf-exempt');
bad('csrff', 'js', 'app.post("/x", {csrf: false}, h)', 'csrf-exempt');
bad('samesite', 'js', 'res.cookie("sid", v, {sameSite: "None"})', 'samesite');
bad('chmod', 'py', 'os.chmod(path, 0o777)', 'world-writable');
bad('mktemp', 'c', 'char *f = mktemp(tpl);', 'mktemp');
bad('execpy', 'py', 'exec(user_code)', 'exec-py');

good('argon', 'py', 'ph.hash(password)');
good('param', 'py', 'cur.execute("SELECT * FROM t WHERE i=%s", [i])');
good('textc', 'js', 'el.textContent = userInput');
good('crng', 'py', 'token = secrets.token_urlsafe(32)');
good('safeyaml', 'py', 'cfg = yaml.safe_load(text)');
good('sha_ok', 'py', 'digest = hashlib.sha256(file_bytes).hexdigest()');
good('exec_ok', 'py', 'subprocess.run([cmd, arg])');
good('doc', 'md', 'use md5(x) and eval(y) here');
good('csrfok', 'py', 'csrf_protect = True');
good('samesite_ok', 'js', 'res.cookie("sid", v, {sameSite: "Lax"})');
good('chmodok', 'py', 'os.chmod(path, 0o600)');
good('mkstemp', 'py', 'fd, path = tempfile.mkstemp()');
good('execjs', 'js', 're.exec(input)');

// vendored-path skip
const vm = path.join(TMP, 'node_modules');
fs.mkdirSync(vm, { recursive: true });
fs.writeFileSync(path.join(vm, 'v.js'), 'eval(x)\n');
if (runScan(path.join(vm, 'v.js')).trim() === '') pass++;
else { fail++; console.log('FALSE+ vendored'); }

// --- config section ---
bad('dbg1', 'py', 'DEBUG = True', 'debug-on');
bad('dbg2', 'env', 'FLASK_ENV=development', 'debug-on');
bad('dbg3', 'py', 'app.run(host="0.0.0.0", debug=True)', 'debug-on');
bad('dirlist', 'conf', 'autoindex on;', 'dir-listing');
bad('banner', 'conf', 'server_tokens on;', 'server-banner');
bad('dav', 'conf', 'dav_methods PUT DELETE MKCOL;', 'http-methods');
bad('defcred', 'yml', 'POSTGRES_PASSWORD: postgres', 'default-cred');
bad('defpw', 'env', 'DB_PASSWORD=changeme', 'default-cred');
bad('croot', 'Dockerfile', 'USER root', 'container-root');
bad('cpriv', 'yml', 'privileged: true', 'container-priv');
bad('bypass', 'py', 'if BYPASS_AUTH: return True', 'test-code');
bad('grant', 'sql', 'GRANT ALL PRIVILEGES ON db.* TO app;', 'default-db-account');
bad('incl', 'php', 'include($_GET["page"]);', 'dynamic-include');
bad('oredir', 'js', 'res.redirect(req.query.next)', 'open-redirect');

good('dbg_off', 'py', 'DEBUG = False');
good('dbg_prod', 'env', 'FLASK_ENV=production');
good('noindex', 'conf', 'autoindex off;');
good('banner_o', 'conf', 'server_tokens off;');
good('realpw', 'yml', 'POSTGRES_PASSWORD: ${DB_SECRET}');
good('cuser', 'Dockerfile', 'USER appuser');
good('redir_ok', 'js', 'res.redirect("/dashboard")');
good('incl_ok', 'php', 'include(PAGES[$key]);');

// --- additional languages ---
// Go
bad('gomd5', 'go', 'h := md5.New()', 'weak-hash');
bad('gosql', 'go', 'db.Query("SELECT * FROM t WHERE i=" + id)', 'sql-concat');
bad('goshell', 'go', 'exec.Command("sh", "-c", cmd)', 'shell');
bad('godeser', 'go', 'gob.NewDecoder(r).Decode(&v)', 'insecure-deserialization');
bad('gorng', 'go', 'token := rand.Intn(1000000)', 'weak-rng');
bad('gocrypto', 'go', 'import "crypto/des"', 'weak-crypto');
bad('gotls', 'go', 'tls.Config{InsecureSkipVerify: true}', 'tls-off');
bad('gopath', 'go', 'os.Open(r.URL.Query().Get("path"))', 'path-traversal');
bad('goredir', 'go', 'http.Redirect(w, r, r.URL.Query().Get("next"), 302)', 'open-redirect');
good('goparam', 'go', 'db.Query("SELECT * FROM t WHERE i=?", id)');
good('gosha', 'go', 'h := sha256.New()');
good('gosafe', 'go', 'exec.Command("ls", "-l")');
good('gocrng', 'go', 'token := crypto/rand.Read(b)');

// Java / Kotlin
bad('javamd5', 'java', 'MessageDigest.getInstance("MD5")', 'weak-hash');
bad('javasql', 'java', 'stmt.executeQuery("SELECT * FROM t WHERE i=" + id)', 'sql-concat');
bad('javadeser', 'java', 'ObjectInputStream(in).readObject()', 'insecure-deserialization');
bad('javaeval', 'java', 'ScriptEngineManager().getEngineByName("js").eval(x)', 'eval');
bad('javarng', 'java', 'token = new Random().nextInt()', 'weak-rng');
bad('javatls', 'java', 'setHostnameVerifier((h,s) -> true)', 'tls-off');
bad('javapath', 'java', 'new File(request.getParameter("p"))', 'path-traversal');
bad('javaredir', 'java', 'response.sendRedirect(request.getParameter("next"))', 'open-redirect');
good('javaparam', 'java', 'ps.setString(1, id)');
good('javasha', 'java', 'MessageDigest.getInstance("SHA-256")');

// Ruby
bad('rubymd5', 'rb', 'Digest::MD5.hexdigest(data)', 'weak-hash');
bad('rubysql', 'rb', 'conn.query("SELECT * FROM t WHERE i=" + id)', 'sql-concat');
bad('rubyshell', 'rb', 'system("ls " + dir)', 'shell');
bad('rubydeser', 'rb', 'YAML.load(text)', 'insecure-deserialization');
bad('rubyeval', 'rb', 'instance_eval(code)', 'eval');
bad('rubyrng', 'rb', 'token = rand(1000000)', 'weak-rng');
bad('rubytls', 'rb', 'OpenSSL::SSL::VERIFY_NONE', 'tls-off');
bad('rubypath', 'rb', 'File.read(params[:file])', 'path-traversal');
bad('rubyredir', 'rb', 'redirect_to params[:next]', 'open-redirect');
good('rubysafe', 'rb', 'YAML.safe_load(text)');
good('rubyparam', 'rb', 'conn.query("SELECT * FROM t WHERE i=?", id)');

// PHP
bad('phpsql', 'php', 'mysqli_query($c, "SELECT * FROM t WHERE i=" . $id)', 'sql-concat');
bad('phpshell', 'php', 'shell_exec("ls " . $dir)', 'shell');
bad('phprng', 'php', '$token = rand(1000000);', 'weak-rng');
bad('phpcrypto', 'php', 'openssl_encrypt($d, "des-ecb", $k)', 'weak-crypto');
bad('phppath', 'php', 'file_get_contents($_GET["file"])', 'path-traversal');
good('phpparam', 'php', 'mysqli_query($c, "SELECT * FROM t WHERE i=?", $id)');
good('phpsafe', 'php', 'password_hash($pw, PASSWORD_ARGON2ID)');

// C#
bad('csmd5', 'cs', 'MD5.Create()', 'weak-hash');
bad('cssql', 'cs', 'cmd.ExecuteReader("SELECT * FROM t WHERE i=" + id)', 'sql-concat');
bad('csdeser', 'cs', 'BinaryFormatter().Deserialize(ms)', 'insecure-deserialization');
bad('cseval', 'cs', 'CSharpScript.EvaluateAsync(code)', 'eval');
bad('csrng', 'cs', 'token = new Random().Next()', 'weak-rng');
bad('cscrypto', 'cs', 'DES.Create()', 'weak-crypto');
bad('cstls', 'cs', 'ServerCertificateValidationCallback = (s,c,h,e) => true', 'tls-off');
bad('csunsafe', 'cs', 'unsafe { fixed (int* p = &x) { } }', 'mem');
good('csparam', 'cs', 'cmd.Parameters.AddWithValue("@id", id)');
good('cssha', 'cs', 'SHA256.Create()');

// Rust
bad('rsmd5', 'rs', 'let h = Md5::new();', 'weak-hash');
bad('rssql', 'rs', 'conn.query(&format!("SELECT * FROM t WHERE i={}", id))', 'sql-concat');
bad('rsshell', 'rs', 'Command::new("sh").arg("-c").arg(cmd)', 'shell');
bad('rsrng', 'rs', 'let token = rand::thread_rng().gen::<u32>();', 'weak-rng');
bad('rscrypto', 'rs', 'use des::Des;', 'weak-crypto');
good('rsparam', 'rs', 'conn.query("SELECT * FROM t WHERE i=$1", &[&id])');
good('rssha', 'rs', 'let h = Sha256::digest(data);');

// --- findings tracking (open -> fixed) ---
const track = path.join(TMP, 'track.jsonl');
const trackFile = path.join(TMP, 'track.py');
fs.writeFileSync(trackFile, 'h = hashlib.md5(data)\n');
spawnSync('node', [SCAN], { input: JSON.stringify({ tool_input: { file_path: trackFile } }), env: { ...process.env, SECURE_CODING_STATE: track, SECURE_CODING_REPORT: 'off' }, encoding: 'utf8' });
const openState = fs.readFileSync(track, 'utf8');
if (/weak-hash/.test(openState) && /"status":"open"/.test(openState)) pass++;
else { fail++; console.log('MISS  track-open'); }

fs.writeFileSync(trackFile, 'h = hashlib.sha256(data)\n');
spawnSync('node', [SCAN], { input: JSON.stringify({ tool_input: { file_path: trackFile } }), env: { ...process.env, SECURE_CODING_STATE: track, SECURE_CODING_REPORT: 'off' }, encoding: 'utf8' });
const fixedState = fs.readFileSync(track, 'utf8');
if (/weak-hash/.test(fixedState) && /"status":"fixed"/.test(fixedState) && /"resolved_at":"[^"]/.test(fixedState)) pass++;
else { fail++; console.log('MISS  track-fixed'); }

// --- partial fix: one occurrence closes, siblings stay open ---
const partial = path.join(TMP, 'partial.jsonl');
const partialFile = path.join(TMP, 'partial.py');
const scanPartial = () => spawnSync('node', [SCAN], {
  input: JSON.stringify({ tool_input: { file_path: partialFile } }),
  env: { ...process.env, SECURE_CODING_STATE: partial, SECURE_CODING_REPORT: 'off' },
  encoding: 'utf8',
});
fs.writeFileSync(partialFile, 'a = hashlib.md5(x)\nb = hashlib.md5(y)\nc = hashlib.md5(z)\n');
scanPartial();
const recsOf = () => fs.readFileSync(partial, 'utf8').split('\n').filter(Boolean).map(JSON.parse)
  .filter(r => r.id === 'weak-hash');
const before = recsOf();
if (before.length === 3 && before.every(r => r.status === 'open')) pass++;
else { fail++; console.log(`MISS  partial-open: ${JSON.stringify(before.map(r => [r.line, r.status]))}`); }

// Fix only the middle one.
fs.writeFileSync(partialFile, 'a = hashlib.md5(x)\nb = hashlib.sha256(y)\nc = hashlib.md5(z)\n');
scanPartial();
const after = recsOf();
const line2 = after.find(r => r.line === 2);
const others = after.filter(r => r.line !== 2);
if (line2 && line2.status === 'fixed' && others.length === 2 && others.every(r => r.status === 'open')) pass++;
else { fail++; console.log(`MISS  partial-fix: ${JSON.stringify(after.map(r => [r.line, r.status]))}`); }

// --- directories are skipped, not read ---
// git lists extensionless dirs (.github, .vscode); reading one used to crash.
uniq('dir-skip');
const dirPath = path.join(TMP, 'a-directory');
fs.mkdirSync(dirPath, { recursive: true });
const dirRun = spawnSync('node', [SCAN, '--files', dirPath], {
  env: { ...process.env, SECURE_CODING_STATE: path.join(TMP, 'dir.jsonl'), SECURE_CODING_REPORT: 'off' },
  encoding: 'utf8',
});
if (dirRun.status === 0 && !/EISDIR/.test(dirRun.stderr || '')) pass++;
else { fail++; console.log(`MISS  dir-skip (status=${dirRun.status}) ${(dirRun.stderr || '').slice(0, 80)}`); }

// --- detect.js ---
const DETECT = path.join(DIR, 'hooks', 'detect.js');
const detectOut = spawnSync('node', [DETECT, DIR], { encoding: 'utf8' });
try {
  const langs = JSON.parse(detectOut.stdout);
  if (langs.includes('javascript')) pass++;
  else { fail++; console.log('MISS  detect-js'); }
} catch { fail++; console.log('MISS  detect-parse'); }

// --- summary.js ---
const SUMMARY = path.join(DIR, 'hooks', 'summary.js');
const sumOut = spawnSync('node', [SUMMARY], { env: { ...process.env, SECURE_CODING_STATE: track }, encoding: 'utf8' });
if (sumOut.stdout.includes('open') && sumOut.stdout.includes('fixed')) pass++;
else { fail++; console.log('MISS  summary'); }

// --- fix.js (run while finding is still open) ---
const FIX = path.join(DIR, 'hooks', 'fix.js');
const fixTrack = path.join(TMP, 'fix.jsonl');
fs.writeFileSync(path.join(TMP, 'fix.py'), 'h = hashlib.md5(data)\n');
spawnSync('node', [SCAN], { input: JSON.stringify({ tool_input: { file_path: path.join(TMP, 'fix.py') } }), env: { ...process.env, SECURE_CODING_STATE: fixTrack, SECURE_CODING_REPORT: 'off' }, encoding: 'utf8' });
const fixOut = spawnSync('node', [FIX, '--id', 'weak-hash'], { env: { ...process.env, SECURE_CODING_STATE: fixTrack }, encoding: 'utf8' });
if (fixOut.stdout.includes('## weak-hash') && fixOut.stdout.includes('MD5')) pass++;
else { fail++; console.log('MISS  fix'); }

// --- sync.js ---
const SYNC = path.join(DIR, 'hooks', 'sync.js');
const syncOut = spawnSync('node', [SYNC], { encoding: 'utf8' });
if (syncOut.stdout.includes('OK:') && syncOut.status === 0) pass++;
else { fail++; console.log('MISS  sync'); }

// --- report smoke test ---
const repOut = path.join(TMP, 'report.html');
spawnSync('node', [REPORT], { env: { ...process.env, SECURE_CODING_STATE: track, SECURE_CODING_REPORT_OUT: repOut }, encoding: 'utf8' });
const rep = fs.readFileSync(repOut, 'utf8');
if (rep.includes('weak-hash') && rep.includes('Authentication') && rep.includes('auditBody')) pass++;
else { fail++; console.log('MISS  report'); }

// --- grep.js ReDoS guard ---
const GREP = path.join(DIR, 'hooks', 'grep.js');
// nested quantifier should fail
const redo1 = spawnSync('node', [GREP, '--regex', '(a+)+$', os.tmpdir()], { encoding: 'utf8' });
if (redo1.status !== 0 && redo1.stderr.includes('nested quantifiers')) pass++;
else { fail++; console.log('MISS  redos-nested'); }
// too-long regex should fail
const longRe = 'a'.repeat(201);
const redo2 = spawnSync('node', [GREP, '--regex', longRe, os.tmpdir()], { encoding: 'utf8' });
if (redo2.status !== 0 && redo2.stderr.includes('too long')) pass++;
else { fail++; console.log('MISS  redos-long'); }
// valid regex should succeed
const redo3 = spawnSync('node', [GREP, '--regex', 'hashlib\\.md5', DIR], { encoding: 'utf8' });
if (redo3.status === 0) pass++;
else { fail++; console.log('MISS  redos-valid'); }

// --- API security patterns ---
bad('ssrf', 'py', 'requests.get(request.args.get("url"))', 'API-1');
bad('ssrfjs', 'js', 'axios.get(req.query.url)', 'API-1');
bad('massassign', 'py', 'User(**request.json)', 'API-3');
bad('massassignjs', 'js', 'Object.assign(user, req.body)', 'API-3');
bad('verboseerr', 'py', 'return str(e)', 'API-8');
bad('verboseerrjs', 'js', 'catch(err){res.send(err)}', 'API-8');

// --- Container security patterns ---
bad('controot', 'Dockerfile', 'USER root', 'C-1');
bad('priv', 'yml', 'privileged: true', 'C-2');
bad('hostnet', 'yml', 'hostNetwork: true', 'C-3');
bad('docksock', 'yml', '/var/run/docker.sock:/var/run/docker.sock', 'C-6');
bad('nohealth', 'Dockerfile', 'HEALTHCHECK NONE', 'C-7');
bad('capall', 'yml', 'add: ["ALL"]', 'C-5');
bad('runas0', 'yml', 'runAsUser: 0', 'C-8');
bad('nolimits', 'yml', 'resources: {}', 'C-10');

// --- Logging security patterns ---
bad('loginject1', 'js', 'console.log(`User ${req.body.name} logged in`)', 'log-inject');
bad('loginject2', 'py', 'logger.info("Input: %s" % user_input)', 'log-inject');
bad('logleak1', 'js', 'console.log("Password:", password)', 'log-leak');
bad('logleak2', 'py', 'logging.info("Token: %s" % token)', 'log-leak');

// --- Password storage patterns ---
bad('pwsplain', 'js', 'const password = "hunter2";', 'pw-slow-hash');
bad('pwsplainpy', 'py', 'self.password = request.form.get("password")', 'pw-slow-hash');

// --- SSRF patterns ---
bad('ssrfjs2', 'js', 'fetch(req.query.url)', 'ssrf');
bad('ssrfpy', 'py', 'requests.get(request.args.get("url"))', 'ssrf');
bad('ssrfgo', 'go', 'http.Get(r.URL.Query().Get("url"))', 'ssrf');

// --- File upload patterns ---
bad('fileup1', 'js', 'multer({ dest: "uploads/" })', 'file-upload');
bad('fileup2', 'py', 'upload = request.files["file"]', 'file-upload');

// --- NoSQL injection patterns ---
bad('nosqli1', 'js', 'db.collection.find({ username: req.body.username })', 'nosql-inject');
bad('nosqli2', 'py', 'collection.find({"$where": request.form.get("q")})', 'nosql-inject');

// --- Good: should not trigger any new patterns ---
good('goodlog', 'js', 'logger.info("User logged in", { userId: user.id })');
good('goodpw', 'js', 'const hash = await bcrypt.hash(password, 12)');
good('goodssrf', 'js', 'fetch(allowlistedUrl)');
good('goodupload', 'js', 'if (file.mimetype === "image/png") { save(file) }');
good('goodnosql', 'js', 'db.collection.find({ username: String(req.body.username) })');

// --- OAuth2 patterns ---
bad('oauth2state', 'js', 'state = req.query.state', 'oauth2-state');
bad('oauth2statepy', 'py', 'state = request.args.get("state")', 'oauth2-state');
bad('oauth2token', 'js', 'jwt.verify(token, key, { verify: false })', 'oauth2-token');
bad('oauth2redirect', 'js', 'redirect_uri = req.query.redirect_uri', 'oauth2-redirect');
bad('oauth2redirectpy', 'py', 'redirect_uri = request.args.get("redirect_uri")', 'oauth2-redirect');

// --- Session fixation patterns ---
bad('sessfix1', 'js', 'req.session.id = params.id', 'session-fixation');
bad('sessfix2', 'py', 'session["id"] = request.args.get("sid")', 'session-fixation');
bad('sessfix3', 'rb', 'session.id = params[:session_id]', 'session-fixation');

// --- WebSocket patterns ---
bad('wsorigin', 'js', 'new WebSocket("ws://localhost:8080")', 'ws-origin');
bad('wsauth', 'js', '.on("connection", (socket) => { /* no auth */ })', 'ws-auth');

// --- Good: should not trigger Phase 2 patterns ---
good('goodoauth', 'js', 'state = generateRandomState(); sessionStorage.setItem("oauth_state", state)');
good('goodsession', 'js', 'req.session.regenerate(() => { res.redirect("/") })');
good('goodws', 'js', 'if (origin === ALLOWED_ORIGIN) { accept(socket) }');

// --- Dockerfile security patterns ---
bad('dockcopy', 'Dockerfile', 'COPY . .', 'docker-copy-secrets');
bad('dockcopyenv', 'Dockerfile', 'COPY .env /app', 'docker-copy-secrets');
bad('docklatest', 'Dockerfile', 'FROM node:latest', 'dockerfile-latest');
bad('dockupgrade', 'Dockerfile', 'RUN apt-get update && apt-get upgrade -y', 'dockerfile-upgrade');
bad('dockenvpw', 'Dockerfile', 'ENV DB_PASSWORD=secret123', 'dockerfile-env-secrets');
bad('dockcurlbash', 'Dockerfile', 'RUN curl -sSL https://example.com/install.sh | bash', 'dockerfile-curl-bash');
bad('dockadd', 'Dockerfile', 'ADD app.js /app', 'dockerfile-add');

// --- Supply chain patterns ---
bad('unpinaction', 'yml', 'uses: actions/checkout@v4', 'unpinned-action');
bad('unpinaction2', 'yml', 'uses: actions/setup-node@main', 'unpinned-action');

// --- K8s patterns ---
bad('hostpath', 'yml', 'hostPath:', 'hostpath');

// --- Good: should not trigger Phase 3 patterns ---
good('gooddocker', 'Dockerfile', 'COPY --chown=node:node package.json package-lock.json ./');
good('goodaction', 'yml', 'uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11');

// --- audit.js ---
const AUDIT = path.join(DIR, 'hooks', 'audit.js');
const auditDir = path.join(TMP, 'audit-project');
fs.mkdirSync(auditDir, { recursive: true });
fs.writeFileSync(path.join(auditDir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 2, packages: {} }));
const auditOut = spawnSync('node', [AUDIT, auditDir], { encoding: 'utf8' });
try {
  const auditData = JSON.parse(auditOut.stdout);
  if (auditData.hasOwnProperty('findings') && auditData.hasOwnProperty('skipped')) pass++;
  else { fail++; console.log('MISS  audit-structure'); }
} catch { fail++; console.log('MISS  audit-parse'); }

// --- SSTI, Prototype Pollution, ReDoS, XXE, Zip Slip ---
bad('sstipy', 'py', 'render_template_string(user_tpl)', 'ssti');
bad('sstijs', 'js', 'ejs.render("<%= " + name, data)', 'ssti');
good('sstiok', 'py', 'render_template("profile.html", name=user_name)');

bad('protojs', 'js', 'Object.assign({}, req.body)', 'prototype-pollution');
good('proto_ok', 'js', 'const safe = Object.create(null); safe[key] = value;');

bad('redosjs', 'js', 'new RegExp(req.query.search)', 'redos-input');
good('redos_ok', 'js', 'const re = new RegExp("^[a-z]+$");');

bad('xxepy', 'py', 'tree = lxml.etree.fromstring(raw_xml)', 'xxe');
good('xxeok', 'py', 'import defusedxml; tree = defusedxml.lxml.fromstring(raw_xml)');

bad('zipslip', 'py', 'tar.extractall(path)', 'zip-slip');
good('zipslip_ok', 'py', 'if is_safe_path(p): tar.extract(p)');

// Regex precedence false-positive guards
good('pyfstr_ok', 'py', 'log_msg = f"processing {item_id}"');
good('pyformat_ok', 'py', 'formatted = "hello {}".format(user)');

// --- Shell script patterns ---
bad('shunquoted', 'sh', 'rm $file', 'unquoted-var');
bad('sheval', 'sh', 'eval $user_input', 'eval-input');
bad('shset', 'sh', 'set +e', 'set-hide-error');
bad('shtest', 'sh', '[ $var == "yes" ]', 'unquoted-test');
good('shquoted', 'sh', 'rm "$file"');
good('shquoted2', 'sh', '[ "$var" == "yes" ]');

// --- Terraform patterns ---
bad('tflocal', 'tf', 'provisioner "local-exec" {', 'provisioner-local');
bad('tfremote', 'tf', 'provisioner "remote-exec" {', 'provisioner-remote');
bad('tfpass', 'tf', 'connection { password = var.db_password }', 'tf-password');
good('tfkey', 'tf', 'connection { private_key = var.ssh_key }');

// --- JWT Security ---
bad('jwt_none', 'ts', 'jwt.verify(token, key, { algorithms: ["none"] })', 'jwt-none-alg');
bad('jwt_hardcoded', 'ts', 'jwt.sign(payload, "secret123")', 'jwt-hardcoded-secret');
bad('jwt_no_ver', 'py', 'jwt.decode(token, verify=False)', 'jwt-no-verify');
good('jwt_ok', 'ts', 'jwt.verify(token, publicKey, { algorithms: ["RS256"] })');

// --- CORS Misconfigurations ---
bad('cors_cred', 'js', 'res.setHeader("Access-Control-Allow-Origin", "*"); res.setHeader("Access-Control-Allow-Credentials", "true")', 'cors-wildcard-credentials');
bad('cors_reflect', 'js', 'res.setHeader("Access-Control-Allow-Origin", req.headers.origin)', 'cors-origin-reflection');
good('cors_ok', 'js', 'if (allowed.has(origin)) res.setHeader("Access-Control-Allow-Origin", origin)');

// --- Insecure Deserialization ---
bad('deser_py', 'py', 'pickle.loads(user_data)', 'insecure-deserialization');
bad('deser_java', 'java', 'ObjectInputStream(stream).readObject()', 'insecure-deserialization');
good('deser_ok', 'py', 'json.loads(user_data)');

// --- LLM & AI Security Patterns ---
bad('llm_inject', 'py', 'openai.chat.completions.create(messages=[{"role": "user", "content": f"prompt {user_input}"}])', 'llm-prompt-injection');
bad('llm_exec', 'py', 'exec(response.choices[0].message.content)', 'llm-unsafe-exec');
bad('rsc_unval', 'ts', '"use server";\nexport async function deleteUser(id) { await db.delete(id); }', 'rsc-unvalidated-action');
good('rsc_val', 'ts', '"use server";\nexport async function deleteUser(raw) { const id = z.string().parse(raw); await db.delete(id); }');
bad('llm_html', 'js', 'element.innerHTML = response.content;', 'llm-output-html');
bad('llm_rag', 'py', 'results = store.similarity_search(query=user_query, k=5)', 'llm-rag-no-filter');
good('llm_rag_ok', 'py', 'results = store.similarity_search(query=user_query, filter={"tenant": tenant_id})');
bad('llm_agency', 'py', 'execute_tool(name, args, auto_approve=True)', 'llm-excessive-agency');
bad('llm_tokens', 'py', 'client.chat.completions.create(model="gpt-4", messages=msgs)', 'llm-unbounded-tokens');
good('llm_tokens_ok', 'py', 'client.chat.completions.create(model="gpt-4", messages=msgs, max_tokens=500)');

// --- High-Entropy Secret Detection ---
bad('sec_aws', 'ts', 'const key = "AKIA1234567890ABCDEF";', 'secret-aws-key');
bad('sec_gh', 'ts', 'const token = "ghp_123456789012345678901234567890123456";', 'secret-github-token');
bad('sec_stripe', 'ts', 'const stripe = "sk_live_1234567890abcdef12345678";', 'secret-stripe-key');
bad('sec_google', 'ts', 'const key = "AIzaSyD1234567890123456789012345678901";', 'secret-google-key');
bad('sec_privkey', 'pem', '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0', 'secret-private-key');
bad('sec_slack', 'ts', 'const u = "https://hooks.slack.com/services/T00000000/B00000000/012345678901234567890123";', 'secret-slack-webhook');
bad('sec_db', 'ts', 'const uri = "postgres://admin:supersecretpassword@db.prod.internal:5432/app";', 'secret-db-url');
good('sec_env', 'ts', 'const key = process.env.AWS_ACCESS_KEY_ID;');

// --- Inline Suppression Comments ---
good('suppress_comment', 'js', 'const x = eval(str); // secure-coding-ignore: eval');
good('suppress_nosec', 'py', 'data = pickle.loads(raw) # nosec: insecure-deserialization, deser');

// --- detect.js modern frameworks ---
const detectNext = spawnSync('node', [DETECT, path.join(TMP)], { encoding: 'utf8' });
// Create a next.config.js to test detection
fs.writeFileSync(path.join(TMP, 'next.config.js'), 'module.exports = {}');
const detectNext2 = spawnSync('node', [DETECT, path.join(TMP)], { encoding: 'utf8' });
try {
  const langs2 = JSON.parse(detectNext2.stdout);
  if (langs2.includes('javascript')) pass++;
  else { fail++; console.log('MISS  detect-next'); }
} catch { fail++; console.log('MISS  detect-next-parse'); }

// --- report.js markdown & SARIF exports ---
const REPORT_SCRIPT = path.join(DIR, 'hooks', 'report.js');
const mdOut = spawnSync('node', [REPORT_SCRIPT, '--markdown'], { encoding: 'utf8' });
if (mdOut.stdout && mdOut.stdout.includes('### 🛡️ Security Scan Summary')) pass++;
else { fail++; console.log('MISS  report-markdown'); }

const sarifOut = spawnSync('node', [REPORT_SCRIPT, '--sarif'], { encoding: 'utf8' });
try {
  const sarifObj = JSON.parse(sarifOut.stdout);
  if (sarifObj.version === '2.1.0' && Array.isArray(sarifObj.runs)) pass++;
  else { fail++; console.log('MISS  report-sarif-schema'); }
} catch { fail++; console.log('MISS  report-sarif-json'); }

// --- fix.js --suggest mode ---
const FIX_SCRIPT = path.join(DIR, 'hooks', 'fix.js');
const fixSuggest = spawnSync('node', [FIX_SCRIPT, '--suggest', 'secret-aws-key'], { encoding: 'utf8' });
if (fixSuggest.stdout.includes('AWS Secrets Manager')) pass++;
else { fail++; console.log('MISS  fix-suggest'); }

// --- Shannon Entropy Secret Detection ---
bad('entropy_sec', 'js', 'const signing_key = "8f9a2b1c4e7d0f3a6b5c4d3e2f1a0b9c";', 'secret-entropy');
bad('entropy_b64', 'js', 'const master_key = "dGhpcyBpcyBhIHJhbmRvbSBrZXkgd2l0aCBoaWdoIGVudHJvcHk=";', 'secret-entropy');
good('entropy_low', 'js', 'const signing_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";');

// --- Secure by Design (SbD) Architecture Patterns ---
bad('sbd_missing_timeout', 'py', 'response = requests.get("https://api.internal/data")', 'sbd-missing-timeout');
good('sbd_with_timeout', 'py', 'response = requests.get("https://api.internal/data", timeout=5.0)');
bad('sbd_legacy_tls', 'py', 'ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_0)', 'sbd-legacy-tls');
good('sbd_modern_tls', 'py', 'ctx = ssl.create_default_context()');
bad('sbd_eval_reflection', 'js', 'const res = eval(req.body.code);', 'eval');

// --- multi-line taint tracking ---
// Regex patterns only fire when the source sits inside the sink call. These
// cover the same bug split across lines, and — just as important — that
// sanitized or out-of-scope code stays clean.
(function taintTests() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const ids = (code, ext) => matchContent(code, 'taint.' + ext, pats).map(h => h.id);

  const flags = (name, code, ext, wanted) => {
    uniq('taint-' + name);
    const got = ids(code, ext);
    if (got.includes(wanted)) pass++;
    else { fail++; console.log(`MISS  taint-${name}: got [${got}] want ${wanted}`); }
  };
  const clean = (name, code, ext) => {
    uniq('taint-clean-' + name);
    const got = ids(code, ext).filter(i => i.startsWith('taint-'));
    if (got.length === 0) pass++;
    else { fail++; console.log(`FALSE+ taint-${name}: ${got}`); }
  };

  flags('phpPath', '$f = $_GET["f"];\nreadfile($f);', 'php', 'taint-path-traversal');
  flags('pySsrf', 'u = request.args["url"]\nrequests.get(u)', 'py', 'taint-ssrf');
  flags('jsSsrf', 'const t = req.query.url;\nawait fetch(t);', 'js', 'taint-ssrf');
  flags('jsCmd', 'const c = req.body.cmd;\nexec(c);', 'js', 'taint-command');
  // One hop through interpolation: req.params -> template -> sink.
  flags('twoHop', 'const p = req.params.name;\nconst full = `/data/${p}`;\nfs.readFileSync(full);', 'js', 'taint-path-traversal');

  clean('sanitized', 'const r = req.query.f;\nconst n = path.basename(r);\nfs.readFileSync(n);', 'js');
  clean('parameterized', 'const id = req.params.id;\ndb.query("SELECT * FROM u WHERE id = ?", [id]);', 'js');
  clean('parsedInt', 'const p = parseInt(req.query.page, 10);\ndb.query("SELECT * LIMIT ?", [p]);', 'js');
  clean('reassigned', 'let t = req.query.url;\nt = DEFAULT;\nawait fetch(t);', 'js');
  // Taint must not cross a function boundary.
  clean('scoped', 'function a(req) {\n  const u = req.query.url;\n}\nfunction b() {\n  fetch(u);\n}', 'js');
  clean('notAssignment', 'const eq = req.query.x == other;\nfetch(other);', 'js');
})();

// --- pattern file hygiene ---
// The exclusion column takes ONE !regex. Writing `!a|!b|!c` makes only `a`
// exclude; `b` and `c` then require a literal `!` in the code and never fire,
// so safe code keeps getting flagged.
(function exclusionSyntax() {
  uniq('pattern-exclusion-syntax');
  const dir = path.join(DIR, 'patterns');
  const offenders = [];
  for (const f of fs.readdirSync(dir).filter(n => n.endsWith('.txt'))) {
    const lines = fs.readFileSync(path.join(dir, f), 'utf8').split(/\r?\n/);
    lines.forEach((line, i) => {
      if (!line || line.startsWith('#')) return;
      const cols = line.split('\t');
      if (cols.length > 3 && cols[3].startsWith('!') && cols[3].slice(1).includes('!')) {
        offenders.push(`${f}:${i + 1} ${cols[0]} -> ${cols[3]}`);
      }
    });
  }
  if (offenders.length === 0) pass++;
  else { fail++; console.log('EXCL malformed exclusion columns:\n  ' + offenders.join('\n  ')); }
})();

// --- CLI argument handling ---
// An unknown flag used to fall through to hook mode and block forever on a
// stdin read. It must fail loudly instead, without breaking real hook input.
(function cliArgs() {
  const runArgs = (args, input) => spawnSync('node', [SCAN, ...args], {
    input: input === undefined ? '' : input,
    env: { ...process.env, SECURE_CODING_STATE: path.join(TMP, 'cli.jsonl'), SECURE_CODING_REPORT: 'off' },
    encoding: 'utf8',
    timeout: 10000,
  });

  const expect = (name, args, input, wantStatus) => {
    uniq('cli-' + name);
    const r = runArgs(args, input);
    if (r.status === wantStatus && !r.error) pass++;
    else { fail++; console.log(`MISS  cli-${name}: status=${r.status} want=${wantStatus}${r.error ? ' err=' + r.error.code : ''}`); }
  };

  expect('help', ['--help'], '', 0);
  expect('unknownFlag', ['--path', '/tmp'], '', 64);
  expect('bogusFlag', ['--bogus'], '', 64);

  // Usage text must actually reach the user, on stderr for the error case.
  uniq('cli-usage-text');
  const u = runArgs(['--nope'], '');
  if (/unknown option/.test(u.stderr) && /Usage:/.test(u.stderr)) pass++;
  else { fail++; console.log('MISS  cli-usage-text'); }

  // Real hook mode (piped JSON) must keep working.
  uniq('cli-hook-mode');
  const hookFile = path.join(TMP, 'cli-hook.js');
  fs.writeFileSync(hookFile, 'eval(x);\n');
  const h = runArgs([], JSON.stringify({ tool_input: { file_path: hookFile } }));
  if (h.status === 2 && /eval/.test(h.stdout)) pass++;
  else { fail++; console.log(`MISS  cli-hook-mode: status=${h.status}`); }
})();

// --- filename-scoped patterns (Dockerfile) ---
// exts are lowercased at load, so a `Dockerfile`-scoped rule only matched a
// lowercase basename — all 19 container rules were unreachable.
(function dockerfileScope() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const ids = (name) => matchContent('USER root', '/x/' + name, pats).map(h => h.id);

  for (const name of ['Dockerfile', 'dockerfile', 'Dockerfile.prod', 'api.Dockerfile']) {
    uniq('dockerfile-' + name);
    if (ids(name).includes('container-root')) pass++;
    else { fail++; console.log(`MISS  dockerfile-${name} (want container-root, got [${ids(name)}])`); }
  }

  // Extensionless files must still be filtered, not exempted from scoping.
  // Extensionless files must be filtered by basename, not exempted from
  // scoping. Asserted on the scoping rule itself: id-level dedupe hides this
  // in matchContent output when a `*` rule shares the id.
  uniq('dockerfile-no-leak');
  const scoped = pats.filter(x => x.exts !== '*' && !x.exts.split(',').includes('dockerfile'));
  const leaks = scoped.filter(x => {
    const want = x.exts.split(','), lb = 'makefile';
    const named = want.some(w => lb === w || lb.startsWith(w + '.') || lb.endsWith('.' + w));
    return want.includes('') || named;
  });
  if (leaks.length === 0) pass++;
  else { fail++; console.log(`MISS  dockerfile-no-leak: ${leaks.length} scoped rules would run on Makefile`); }

  // A scoped rule must not bleed across languages.
  uniq('dockerfile-lang-scope');
  const goOnJs = matchContent('db.Query("SELECT * FROM t WHERE i=" + id)', 'x.js', pats)
    .map(h => h.id).includes('sql-concat');
  if (!goOnJs) pass++;
  else { fail++; console.log('MISS  dockerfile-lang-scope: go rule fired on .js'); }
})();

// --- per-occurrence reporting ---
// The same id on several lines is several findings, so fixing one does not
// silently close the others.
(function occurrenceTests() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();

  uniq('occ-multi');
  const code = [
    'db.query("SELECT * FROM a WHERE x=\'" + a + "\'");',
    'db.query("SELECT * FROM b WHERE y=\'" + b + "\'");',
    'db.query("SELECT * FROM c WHERE z=\'" + c + "\'");',
  ].join('\n');
  const sql = matchContent(code, 'occ.js', pats).filter(h => h.id === 'sql-concat');
  if (sql.length === 3 && sql.map(h => h.line).join(',') === '1,2,3') pass++;
  else { fail++; console.log(`OCC multi: got ${sql.length} hits at [${sql.map(h => h.line)}], want 3 at 1,2,3`); }

  // A pathological file must not flood the report.
  uniq('occ-cap');
  const many = Array.from({ length: 30 }, (_, i) => `eval(x${i});`).join('\n');
  const capped = matchContent(many, 'cap.js', pats).filter(h => h.id === 'eval');
  if (capped.length === 20) pass++;
  else { fail++; console.log(`OCC cap: got ${capped.length}, want 20`); }

  // A vector-search rule must not fire on ordinary SQL.
  uniq('occ-rag-not-sql');
  const rag = matchContent('db.query("SELECT * WHERE x=" + req.query.x);', 'r.js', pats);
  if (!rag.some(h => h.id === 'llm-rag-no-filter')) pass++;
  else { fail++; console.log('OCC rag: llm-rag-no-filter fired on plain SQL'); }
})();

// Guard: no unhandled same-line id overlap across a corpus of known-bad code.
// Fails when a NEW pattern double-reports a defect that an existing rule covers.
(function overlapGuard() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const corpus = [
    ['py', 'obj = pickle.loads(body)'], ['py', 'cfg = yaml.load(text)'],
    ['js', 'eval(req.body.code);'], ['js', 'new Function(req.body.x);'],
    ['py', 'os.system("ls " + cmd)'], ['py', 'subprocess.run(cmd, shell=True)'],
    ['js', 'const k = "AKIAIOSFODNN7EXAMPLE";'], ['py', 'h = hashlib.md5(p)'],
    ['js', 'el.innerHTML = req.query.x;'], ['py', 'cur.execute(f"SELECT * FROM t WHERE i={i}")'],
    ['js', 'jwt.verify(t, k, {algorithms:["none"]});'],
  ];
  // Known-distinct defects that legitimately share a line.
  const ALLOWED = new Set(['sbd-missing-timeout + tls-off']);
  const offenders = [];
  for (const [ext, code] of corpus) {
    const byLine = {};
    for (const h of matchContent(code, 'ov.' + ext, pats)) (byLine[h.line] ||= []).push(h.id);
    for (const ids of Object.values(byLine)) {
      const uniqIds = [...new Set(ids)];
      for (let i = 0; i < uniqIds.length; i++) for (let j = i + 1; j < uniqIds.length; j++) {
        const pair = [uniqIds[i], uniqIds[j]].sort().join(' + ');
        if (!ALLOWED.has(pair)) offenders.push(`${pair}  (${code})`);
      }
    }
  }
  uniq('dedupe-overlap-guard');
  if (offenders.length === 0) pass++;
  else { fail++; console.log('OVERLAP unhandled same-line ids:\n  ' + offenders.join('\n  ')); }
})();

// --- same-line duplicate suppression ---
// One defect reports one id; a specific finding supersedes the generic one.
// Two genuinely different defects on one line must BOTH still report.
(function dedupeTests() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const ids = (code, ext) => matchContent(code, 'dedupe.' + ext, pats).map(h => h.id);

  const only = (name, code, ext, wanted, absent) => {
    uniq('dedupe-' + name);
    const got = ids(code, ext);
    if (got.includes(wanted) && !absent.some(a => got.includes(a))) pass++;
    else { fail++; console.log(`DEDUPE ${name}: got [${got}] want ${wanted} without [${absent}]`); }
  };

  only('awsKey', 'const k = "AKIAIOSFODNN7EXAMPLE";', 'js', 'secret-aws-key', ['secret', 'secret-entropy']);
  only('jwtNone', 'jwt.verify(t, k, {algorithms:["none"]});', 'js', 'jwt-none-alg', ['jwt']);
  only('evalRce', 'eval(req.body.code);', 'js', 'eval', ['sbd-dynamic-eval-reflection']);

  // Distinct defects: disabled cert check AND missing timeout are both real.
  uniq('dedupe-distinct');
  const got = ids('requests.get(url, verify=False)', 'py');
  if (got.includes('tls-off') && got.includes('sbd-missing-timeout')) pass++;
  else { fail++; console.log(`DEDUPE distinct: lost a real finding, got [${got}]`); }
})();
good('sbd_safe_parser', 'js', 'const res = JSON.parse(req.body.data);');
bad('sbd_unauth_route', 'js', 'app.get("/admin/users", handler);', 'sbd-unauthenticated-route');
good('sbd_auth_route', 'js', 'app.get("/admin/users", authenticate, handler);');

// --- IoT & Embedded Systems Security Patterns (AS ETSI EN 303 645) ---
bad('iot_mqtt_plain', 'js', 'const client = mqtt.connect("mqtt://broker.hivemq.com:1883");', 'iot-unencrypted-mqtt');
good('iot_mqtts_secure', 'js', 'const client = mqtt.connect("mqtts://broker.hivemq.com:8883", { cert, key });');
bad('iot_coap_plain', 'js', 'const req = coap.request("coap://sensor.local/temp");', 'iot-unencrypted-coap');
good('iot_coaps_secure', 'js', 'const req = coap.request("coaps://sensor.local/temp");');
bad('iot_debug_jtag', 'c', '#define ENABLE_JTAG 1', 'iot-debug-interface');
good('iot_debug_disabled', 'c', '#define ENABLE_JTAG 0');
bad('iot_ota_unverified', 'c', 'flash_write(OTA_SLOT, buffer, len);', 'iot-ota-no-verify');
good('iot_ota_verified', 'c', 'if (verify_signature(buffer, sig, pubkey)) { flash_write(OTA_SLOT, buffer, len); }');
bad('iot_flash_key', 'c', '#define FIRMWARE_KEY "0123456789abcdef0123456789abcdef"', 'iot-hardcoded-flash-key');
good('iot_flash_no_key', 'c', '#define FIRMWARE_VERSION "1.2.3"');

// --- scan.js CLI --files mode ---
const testScanFile = path.join(TMP, 'test-cli.js');
fs.writeFileSync(testScanFile, 'const evalCode = eval(input);');
const scanCliOut = spawnSync('node', [SCAN, '--files', testScanFile], {
  env: { ...process.env, SECURE_CODING_STATE: path.join(TMP, 'findings.jsonl'), SECURE_CODING_REPORT: 'off' },
  encoding: 'utf8',
});
if (scanCliOut.stdout.includes('Line 1') || scanCliOut.stdout.includes('eval')) pass++;
else { fail++; console.log('MISS  scan-cli-files'); }

// --- sbom.js CycloneDX & SPDX generation ---
const SBOM_SCRIPT = path.join(DIR, 'hooks', 'sbom.js');
const cdxOut = spawnSync('node', [SBOM_SCRIPT, '--format', 'cyclonedx'], { encoding: 'utf8' });
try {
  const cdxObj = JSON.parse(cdxOut.stdout);
  if (cdxObj.bomFormat === 'CycloneDX' && cdxObj.specVersion === '1.5') pass++;
  else { fail++; console.log('MISS  sbom-cyclonedx'); }
} catch { fail++; console.log('MISS  sbom-cyclonedx-parse'); }

const spdxOut = spawnSync('node', [SBOM_SCRIPT, '--format', 'spdx'], { encoding: 'utf8' });
try {
  const spdxObj = JSON.parse(spdxOut.stdout);
  if (spdxObj.spdxVersion.startsWith('SPDX')) pass++;
  else { fail++; console.log('MISS  sbom-spdx'); }
} catch { fail++; console.log('MISS  sbom-spdx-parse'); }

// BSI AI-SBOM 7 Clusters test
const aiSbomOut = spawnSync('node', [SBOM_SCRIPT, '--format', 'cyclonedx', '--ai'], { encoding: 'utf8' });
try {
  const aiObj = JSON.parse(aiSbomOut.stdout);
  const hasAiModel = aiObj.components && aiObj.components.some(c => c.type === 'machine-learning-model' && c.modelCard);
  if (hasAiModel) pass++;
  else { fail++; console.log('MISS  sbom-ai-clusters'); }
} catch { fail++; console.log('MISS  sbom-ai-parse'); }

// ACSC/CISA VEX Exploitability test
const vexSbomOut = spawnSync('node', [SBOM_SCRIPT, '--format', 'cyclonedx', '--vex'], { encoding: 'utf8' });
try {
  const vexObj = JSON.parse(vexSbomOut.stdout);
  if (Array.isArray(vexObj.vulnerabilities)) pass++;
  else { fail++; console.log('MISS  sbom-vex-generation'); }
} catch { fail++; console.log('MISS  sbom-vex-parse'); }


// --- config.js CLI ---
const CFG_SCRIPT = path.join(DIR, 'hooks', 'config.js');
const cfgOut = spawnSync('node', [CFG_SCRIPT, '--get', 'failOn'], { encoding: 'utf8' });
if (cfgOut.stdout.trim() === 'high') pass++;
else { fail++; console.log('MISS  config-get'); }

// --- fix.js --apply autofix engine ---
const fixTestFile = path.join(TMP, 'autofix-test.js');
fs.writeFileSync(fixTestFile, 'const token = Math.random();\n');
const autofixState = path.join(TMP, 'autofix-state.jsonl');
fs.writeFileSync(autofixState, JSON.stringify({ file: fixTestFile, id: 'weak-rng', status: 'open' }) + '\n');
spawnSync('node', [FIX_SCRIPT, '--apply'], {
  env: { ...process.env, SECURE_CODING_STATE: autofixState },
  encoding: 'utf8',
});
const fixedContent = fs.readFileSync(fixTestFile, 'utf8');
if (fixedContent.includes('randomBytes')) pass++;
else { fail++; console.log('MISS  autofix-apply'); }

fs.rmSync(TMP, { recursive: true, force: true });

// --- clean.js tests ---
const CLEAN = path.join(DIR, 'hooks', 'clean.js');
const cleanDir = path.join(TMP, 'clean-project');
fs.mkdirSync(cleanDir, { recursive: true });

function runClean(file) {
  const r = spawnSync('node', [CLEAN, '--file', file, '--json'], {
    encoding: 'utf8',
  });
  try { return JSON.parse(r.stdout); } catch { return []; }
}

function cleanBad(name, ext, content, expectedId) {
  uniq('clean-' + name);
  const file = path.join(cleanDir, `${name}.${ext}`);
  fs.writeFileSync(file, content);
  const hits = runClean(file);
  if (hits.some(h => h.id === expectedId)) pass++;
  else { fail++; console.log(`MISS  clean-${name} (want ${expectedId})`); }
}

function cleanGood(name, ext, content) {
  uniq('clean-' + name);
  const file = path.join(cleanDir, `${name}.${ext}`);
  fs.writeFileSync(file, content);
  const hits = runClean(file);
  if (hits.length === 0) pass++;
  else { fail++; console.log(`FALSE+ clean-${name}: ${hits.map(h => h.id).join(', ')}`); }
}

// N3: Magic numbers
cleanBad('magic', 'js', 'setTimeout(restart, 86400000)', 'cc-magic-number');
cleanGood('noMagic', 'js', 'const MILLISECONDS_PER_DAY = 86400000');
cleanGood('okNum', 'js', 'if (x === 1) { return true; }');
cleanGood('okStatus', 'js', 'res.status(404).send("not found");');

// F1: Multi-responsibility function
cleanBad('andFunc', 'js', 'function emailAndNotify(user) { }', 'cc-multi-responsibility');
cleanGood('singleFunc', 'js', 'function emailUser(user) { }');
cleanGood('expandAllFunc', 'js', 'function expandAll() { return true; }');
cleanGood('handleCmdFunc', 'js', 'const handleCommand = () => {};');

// F2: Too many params
cleanBad('manyParams', 'js', 'function createMenu(title, body, buttonText, cancellable, extra) { }', 'cc-too-many-params');
cleanGood('fewParams', 'js', 'function createMenu(options) { }');

// N5: Unneeded context
cleanGood('unneededCtxOk', 'js', 'const config = { maxAge: 10, statusCode: 200, itemCount: 5 };');

// S4: Negative conditional
cleanGood('guardClauseOk', 'js', 'if (!isValid) { return false; }');

// C2: Commented-out code (3+ consecutive)
cleanBad('commentedCode', 'js', '// const x = 1;\n// const y = 2;\n// const z = 3;', 'cc-commented-code');
cleanGood('realComment', 'js', '// This is a real comment\nconst count = 1;');

// E1: Swallowed error
cleanBad('emptyCatch', 'js', 'try { run(); } catch (e) { }', 'cc-swallowed-error');
cleanGood('handledCatch', 'js', 'try { run(); } catch (e) { log(e); }');

// N1: Single-letter var
cleanBad('singleLetter', 'js', 'const x = getData();', 'cc-single-letter-var');
cleanGood('goodName', 'js', 'const data = getData();');

// C1: Dead code (code after return)
cleanBad('deadCode', 'js', 'function f() {\n  return 1;\n  console.log("dead");\n}', 'cc-dead-code');
// Indentation-scoped languages close a block by dedenting, not with a brace.
cleanGood('deadCodePyDedent', 'py', 'def a():\n    return 1\n\ndef b():\n    return 2\n');
cleanGood('deadCodePyContinue', 'py', 'def b():\n    for i in range(3):\n        if i:\n            continue\n        print(i)\n');
cleanBad('deadCodePyReal', 'py', 'def a():\n    return 1\n    print("dead")\n', 'cc-dead-code');
cleanGood('noDeadCode', 'js', 'function f() {\n  return 1;\n}');

// --list flag
const listOut = spawnSync('node', [CLEAN, '--list'], { encoding: 'utf8' });
if (listOut.stdout.includes('cc-magic-number') && listOut.stdout.includes('cc-multi-responsibility')) pass++;
else { fail++; console.log('MISS  clean-list'); }

// --count flag
const countOut = spawnSync('node', [CLEAN, '--file', path.join(cleanDir, 'magic.js'), '--count'], { encoding: 'utf8' });
if (countOut.stdout.trim() === '1') pass++;
else { fail++; console.log(`MISS  clean-count (want 1, got ${countOut.stdout.trim()})`); }

fs.rmSync(cleanDir, { recursive: true, force: true });

// --- mcp/server.js JSON-RPC tests ---
const { processMessage } = require('../mcp/server.js');

// 1. initialize
const initRes = processMessage({ jsonrpc: '2.0', id: 1, method: 'initialize' });
if (initRes && initRes.result && initRes.result.serverInfo && initRes.result.serverInfo.name === 'secure-coding-mcp') pass++;
else { fail++; console.log('MISS  mcp-initialize'); }

// 2. tools/list
const toolsRes = processMessage({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
if (toolsRes && toolsRes.result && Array.isArray(toolsRes.result.tools) && toolsRes.result.tools.length >= 6) pass++;
else { fail++; console.log('MISS  mcp-tools-list'); }

// 3. tools/call secure_code_scan
const scanCallRes = processMessage({
  jsonrpc: '2.0',
  id: 3,
  method: 'tools/call',
  params: { name: 'secure_code_scan', arguments: { code: 'const key = "AKIA1111111111111111";' } },
});
if (scanCallRes && scanCallRes.result && scanCallRes.result.content && scanCallRes.result.content[0].text.includes('aws-key')) pass++;
else { fail++; console.log('MISS  mcp-tools-call-scan'); }

// 4. tools/call generate_ai_sbom
const sbomCallRes = processMessage({
  jsonrpc: '2.0',
  id: 4,
  method: 'tools/call',
  params: { name: 'generate_ai_sbom', arguments: { format: 'cyclonedx' } },
});
if (sbomCallRes && sbomCallRes.result && sbomCallRes.result.content && sbomCallRes.result.content[0].text.includes('CycloneDX')) pass++;
else { fail++; console.log('MISS  mcp-tools-call-sbom'); }

// --- Secret Redaction / Masking Tests ---
const { matchContent: scanMatchContent, loadPatterns: scanLoadPatterns } = require('../hooks/scan.js');
const allPatterns = scanLoadPatterns();
const maskedScanResults = scanMatchContent('const apiKey = "AKIAIOSFODNN7EXAMPLE";', 'test.js', allPatterns);
if (maskedScanResults.length > 0 && maskedScanResults[0].snippet.includes('AKIA') && maskedScanResults[0].snippet.includes('******')) {
  pass++;
} else {
  fail++; console.log('MISS  secret-masking-aws');
}

// --- Pre-Commit Hooks Manifest Test ---
const preCommitYaml = path.join(DIR, '.pre-commit-hooks.yaml');
if (fs.existsSync(preCommitYaml)) {
  const yamlContent = fs.readFileSync(preCommitYaml, 'utf8');
  if (yamlContent.includes('secure-coding-scan') && yamlContent.includes('secure-coding-clean') && yamlContent.includes('secure-coding-audit')) {
    pass++;
  } else {
    fail++; console.log('MISS  pre-commit-yaml-ids');
  }
} else {
  fail++; console.log('MISS  pre-commit-yaml-exists');
}

// --- Report Generation Test ---
const reportOut = spawnSync('node', [REPORT, '--markdown'], { encoding: 'utf8' });
if (reportOut.status === 0 && reportOut.stdout.includes('Security Scan Summary')) {
  pass++;
} else {
  fail++; console.log('MISS  report-markdown-gen');
}

console.log('---');
console.log(`pass=${pass} fail=${fail}`);
process.exit(fail === 0 ? 0 : 1);



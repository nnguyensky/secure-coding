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

// Redirect all run state into TMP before anything requires scan.js. Tests that
// call scanSingleFile() in-process would otherwise write fixtures into the real
// checks/findings.jsonl and leave the repo reporting a finding it does not have.
process.env.SECURE_CODING_STATE = process.env.SECURE_CODING_STATE || path.join(TMP, 'findings.jsonl');
process.env.SECURE_CODING_AUDIT = process.env.SECURE_CODING_AUDIT || path.join(TMP, 'audit.json');
process.env.SECURE_CODING_REPORT = 'off';

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

// --- A10 Mishandling of Exceptional Conditions ---
// The scanner previously found nothing on any of these; A10 had 3 rules for
// 24 CWEs. Negative cases matter most here — `pass` and `return True` appear
// constantly in correct code.
(function a10Rules() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const hit = (code, ext, id) => matchContent(code, 'a10.' + ext, pats).some(h => h.id === id);

  const yes = (name, code, ext, id) => {
    uniq('a10-' + name);
    if (hit(code, ext, id)) pass++;
    else { fail++; console.log(`MISS  a10-${name} (want ${id})`); }
  };
  const no = (name, code, ext, id) => {
    uniq('a10-' + name);
    if (!hit(code, ext, id)) pass++;
    else { fail++; console.log(`FALSE+ a10-${name} (${id}): ${code.slice(0, 46)}`); }
  };

  yes('pyPass', 'try:\n    x()\nexcept Exception:\n    pass\n', 'py', 'swallowed-exception');
  yes('jsEmptyCatch', 'try { await verify(t); } catch (e) { }', 'js', 'swallowed-exception');
  yes('failOpenJs', 'try { auth(); } catch (e) { return true; }', 'js', 'fail-open-catch');
  yes('failOpenPy', 'try:\n    verify(t)\nexcept:\n    authorized = True\n', 'py', 'fail-open-catch');
  yes('bareExcept', 'except:', 'py', 'broad-except');
  yes('goDiscard', 'result, _ := Authorize(user)', 'go', 'unchecked-error');
  yes('stackToClient', 'res.status(500).send(err.stack);', 'js', 'error-detail-exposed');
  yes('pyTraceback', 'return traceback.format_exc()', 'py', 'error-detail-exposed');
  yes('emptyUncaught', "process.on('uncaughtException', () => {});", 'js', 'uncaught-handler-empty');
  yes('goRecover', 'defer func() { recover() }()', 'go', 'recover-empty');

  // `pass` is ordinary Python: abstract methods, exception subclasses, Protocols.
  no('abstractPass', '@abstractmethod\ndef run(self):\n    pass\n', 'py', 'swallowed-exception');
  no('exceptionSubclass', 'class MyError(Exception):\n    pass\n', 'py', 'swallowed-exception');
  no('handledExcept', 'except ValueError as e:\n    logger.exception("failed")\n    raise\n', 'py', 'swallowed-exception');
  no('plainReturnTrue', 'def check(u):\n    if u.is_admin:\n        return True\n', 'py', 'fail-open-catch');
  no('genericError', 'res.status(500).send("Internal error");', 'js', 'error-detail-exposed');
  no('loggedTrace', 'logger.error(traceback.format_exc())', 'py', 'error-detail-exposed');
  no('errChecked', 'result, err := Authorize(user)', 'go', 'unchecked-error');
  no('idiomaticDiscard', 'v, _ := strconv.Atoi(s)', 'go', 'unchecked-error');
  no('handlerLogs', "process.on('uncaughtException', (e) => { log(e); process.exit(1); });", 'js', 'uncaught-handler-empty');
})();

// --- context-sensitive rules ---
// Validated against a real Tauri/Rust app that produced 24 findings, all false
// positives: every `unsafe {}` (mandatory for FFI), every `0o777` literal (a
// chmod parser), and MD5 used as a file checksum.
(function contextRules() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const hit = (code, ext, id) => matchContent(code, 'ctx.' + ext, pats).some(h => h.id === id);

  const yes = (name, code, ext, id) => {
    uniq('ctx-' + name);
    if (hit(code, ext, id)) pass++;
    else { fail++; console.log(`MISS  ctx-${name} (want ${id}): ${code.slice(0, 50)}`); }
  };
  const no = (name, code, ext, id) => {
    uniq('ctx-' + name);
    if (!hit(code, ext, id)) pass++;
    else { fail++; console.log(`FALSE+ ctx-${name} (${id}): ${code.slice(0, 50)}`); }
  };

  // world-writable: the alternation used to bind at top level, so a bare
  // 0o777 literal matched with no chmod at all.
  no('maskLiteral', 'let valid_mask = 0o7777;', 'rs', 'world-writable');
  no('octalAssert', 'assert_eq!(parse_octal("777").unwrap(), 0o777);', 'rs', 'world-writable');
  no('bitClear', "'a' => mode &= !0o777,", 'rs', 'world-writable');
  no('safeMode', 'chmod(path, 0o644)', 'py', 'world-writable');
  yes('chmod777', 'os.chmod(p, 0o777)', 'py', 'world-writable');
  yes('chmodSync', 'fs.chmodSync(f, 0o777)', 'js', 'world-writable');
  yes('chmodShell', 'chmod -R 777 /data', 'sh', 'world-writable');

  // mem: FFI requires unsafe and is not a defect; flag the operation instead.
  no('ffiUnsafe', 'unsafe { winapi::um::aclapi::GetAceCount(a) }', 'rs', 'mem');
  no('unsafeOpen', 'let result = unsafe {', 'rs', 'mem');
  yes('transmute', 'unsafe { std::mem::transmute::<u32,f32>(x) }', 'rs', 'mem');
  yes('fromRawParts', 'let s = unsafe { std::slice::from_raw_parts(p, len) };', 'rs', 'mem');
  yes('getUnchecked', 'let v = unsafe { buf.get_unchecked(i) };', 'rs', 'mem');

  // weak-hash: MD5 is legitimate for non-security checksums.
  no('md5Checksum', 'let mut md5 = md5::Md5::new(); // file integrity checksum', 'rs', 'weak-hash');
  yes('md5Bare', 'let h = md5::Md5::new();', 'rs', 'weak-hash');
})();

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

// --- CWE taxonomy reaches SARIF ---
// GitHub code scanning keys on external/cwe/cwe-N tags; a finding without one
// lands as an untyped alert.
(function cweSarif() {
  const cweFile = path.join(TMP, 'cwe.jsonl');
  const src = path.join(TMP, 'cwe-src.js');
  fs.writeFileSync(src, 'db.query("SELECT * FROM t WHERE a=\'" + a + "\'");\n');
  spawnSync('node', [SCAN, '--files', src], {
    env: { ...process.env, SECURE_CODING_STATE: cweFile, SECURE_CODING_REPORT: 'off' },
    encoding: 'utf8',
  });
  const out = spawnSync('node', [path.join(DIR, 'hooks', 'report.js'), '--sarif'], {
    env: { ...process.env, SECURE_CODING_STATE: cweFile, SECURE_CODING_REPORT: 'off' },
    encoding: 'utf8',
  });
  uniq('cwe-sarif');
  try {
    const rules = JSON.parse(out.stdout).runs[0].tool.driver.rules;
    const rule = rules.find(r => r.id === 'sql-concat');
    const tags = (rule && rule.properties && rule.properties.tags) || [];
    if (tags.includes('external/cwe/cwe-89') && /cwe.mitre.org/.test(rule.helpUri)) pass++;
    else { fail++; console.log(`MISS  cwe-sarif: tags=${JSON.stringify(tags)}`); }
  } catch (e) { fail++; console.log(`MISS  cwe-sarif: ${e.message}`); }

  // fixes.md must carry the CWE for the ids the map claims.
  uniq('cwe-fixes-annotated');
  const fixes = fs.readFileSync(path.join(DIR, 'checks', 'fixes.md'), 'utf8');
  const need = ['sql-concat', 'shell', 'xss-sink', 'weak-hash', 'taint-ssrf',
                'API-1', 'C-1', 'iot-debug-interface', 'llm-prompt-injection'];
  const bad = need.filter(id => {
    const m = fixes.match(new RegExp('^## ' + id + '\\n([^\\n]*)', 'm'));
    return !m || !/CWE-\d+/.test(m[1]);
  });
  if (bad.length === 0) pass++;
  else { fail++; console.log(`MISS  cwe-fixes-annotated: ${bad.join(', ')}`); }
})();

// Every fixes.md block must carry a CWE — a finding without one lands as an
// untyped alert in code scanning.
(function cweAllBlocks() {
  uniq('cwe-all-blocks');
  const fixes = fs.readFileSync(path.join(DIR, 'checks', 'fixes.md'), 'utf8');
  const lines = fixes.split('\n');
  const bad = [];
  lines.forEach((l, i) => {
    if (!l.startsWith('## ')) return;
    const meta = lines[i + 1] || '';
    if (!/CWE-\d+/.test(meta)) bad.push(l.slice(3));
  });
  if (bad.length === 0) pass++;
  else { fail++; console.log(`MISS  cwe-all-blocks: ${bad.length} without CWE (${bad.slice(0, 4).join(', ')})`); }
})();

// --- BSI AI-SBOM: all 7 clusters present ---
(function aiSbomClusters() {
  const { generateAiClusters, countAiTodos } = require('./sbom.js');
  const comp = generateAiClusters()[0];
  const props = comp.properties || [];
  const clusters = new Set(props
    .filter(p => p.name.startsWith('bsi:cluster:'))
    .map(p => p.name.split(':')[2]));

  uniq('ai-sbom-7-clusters');
  const want = ['metadata', 'slp', 'models', 'dp', 'infra', 'sp', 'kpi'];
  const missing = want.filter(c => !clusters.has(c));
  if (missing.length === 0) pass++;
  else { fail++; console.log(`MISS  ai-sbom-7-clusters: no ${missing.join(', ')}`); }

  // Every element the BSI document names must be emitted, not just some.
  uniq('ai-sbom-elements');
  const { BSI_ELEMENTS } = require('./sbom.js');
  const names = new Set(props.map(p => p.name));
  const absent = BSI_ELEMENTS
    .map(([c, e]) => `bsi:cluster:${c}:${e}`)
    .filter(n => !names.has(n));
  if (absent.length === 0) pass++;
  else { fail++; console.log(`MISS  ai-sbom-elements: ${absent.length} absent, e.g. ${absent[0]}`); }

  // Unknown values must be an explicit TODO, never a plausible fake that could
  // ship as if it were real data.
  uniq('ai-sbom-todo-marked');
  const { todo, total } = countAiTodos([comp]);
  if (todo > 0 && total >= 40 && todo <= total) pass++;
  else { fail++; console.log(`MISS  ai-sbom-todo-marked: todo=${todo} total=${total}`); }

  // The scaffold must not invent model metrics.
  uniq('ai-sbom-no-fake-metrics');
  const metrics = comp.modelCard?.quantitativeAnalysis?.performanceMetrics || [];
  if (metrics.length === 0) pass++;
  else { fail++; console.log(`MISS  ai-sbom-no-fake-metrics: ${metrics.length} invented metrics`); }
})();

// --- Done Gate enforcement ---
// The manual review is the only thing covering IDOR, missing authz and
// fail-open. As prose it was skippable; gate.js makes it fail closed.
(function doneGate() {
  const GATE = path.join(TMP, 'gate.json');
  const run = (...a) => spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), ...a], {
    env: { ...process.env, SECURE_CODING_GATE: GATE }, encoding: 'utf8',
  });
  try { fs.unlinkSync(GATE); } catch {}

  uniq('gate-empty-fails');
  if (run('--check', '--all').status === 2) pass++;
  else { fail++; console.log('MISS  gate-empty-fails: an unanswered gate must exit 2'); }

  // A non-answer looks reviewed and is not — worse than silence.
  uniq('gate-rejects-nonanswer');
  const r = run('--answer', 'ownership', 'yes');
  if (r.status === 64 && /does not name a check/.test(r.stderr)) pass++;
  else { fail++; console.log(`MISS  gate-rejects-nonanswer: status=${r.status}`); }

  // A blocklist only catches filler someone thought of. These are the answers
  // an agent under pressure to finish would actually try.
  uniq('gate-rejects-filler');
  const junk = ['x', '-', 'TODO', 'handled', 'none', 'nothing', 'see above', 'ok done', 'N/A'];
  const slipped = junk.filter(j => run('--answer', 'ownership', j).status === 0);
  if (slipped.length === 0) pass++;
  else { fail++; console.log(`MISS  gate-rejects-filler: accepted ${JSON.stringify(slipped)}`); }

  // ...without rejecting answers that genuinely name a check.
  uniq('gate-accepts-real');
  const real = ['requireAdmin middleware', 'scoped by userId predicate',
                'catch denies with 403', 'N/A — no data access in this change'];
  const blocked = real.filter(x => run('--answer', 'ownership', x).status !== 0);
  if (blocked.length === 0) pass++;
  else { fail++; console.log(`MISS  gate-accepts-real: rejected ${JSON.stringify(blocked)}`); }

  uniq('gate-rejects-unknown');
  if (run('--answer', 'nope', 'x').status === 64) pass++;
  else { fail++; console.log('MISS  gate-rejects-unknown'); }

  uniq('gate-complete-passes');
  run('--answer', 'ownership', 'scoped by userId predicate');
  run('--answer', 'authorization', 'requireAdmin middleware');
  run('--answer', 'taint', 'N/A — no request values in this change');
  run('--answer', 'failure-direction', 'catch denies with 403');
  if (run('--check', '--all').status === 0) pass++;
  else { fail++; console.log('MISS  gate-complete-passes'); }

  // The ref must follow the repo being reviewed, not wherever gate.js lives —
  // otherwise a global install and the skill copy disagree and answers never
  // resolve, silently blocking every commit.
  uniq('gate-ref-follows-cwd');
  const fromSkill = spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--status'], {
    cwd: DIR, env: { ...process.env, SECURE_CODING_GATE: GATE }, encoding: 'utf8' }).stdout;
  const fromTmp = spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--status'], {
    cwd: TMP, env: { ...process.env, SECURE_CODING_GATE: GATE }, encoding: 'utf8' }).stdout;
  const ref = t => (t.match(/Done Gate @ (\S+)/) || [])[1];
  if (ref(fromSkill) && ref(fromTmp) && ref(fromSkill) !== ref(fromTmp)) pass++;
  else { fail++; console.log(`MISS  gate-ref-follows-cwd: ${ref(fromSkill)} vs ${ref(fromTmp)}`); }

  // Answers must not carry forward to a different commit.
  uniq('gate-expires-on-new-commit');
  const d = JSON.parse(fs.readFileSync(GATE, 'utf8'));
  d.ref = 'stale000000';
  fs.writeFileSync(GATE, JSON.stringify(d));
  if (run('--check', '--all').status === 2) pass++;
  else { fail++; console.log('MISS  gate-expires-on-new-commit: stale answers still passed'); }
})();

// --- logging rules match values, not prose ---
// Found on a real repo: a WCAG script logging a count was reported as a
// critical secret leak, because "theme token(s)" contains "token" and
// "${tokenFailures." contains "res.".
(function loggingPrecision() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const ids = (code) => matchContent(code, 'lg.js', pats)
    .filter(h => h.id.startsWith('log-')).map(h => h.id);

  uniq('log-rules-ignore-prose');
  const prose = [
    'console.error(`✗ contrast: ${tokenFailures.length} theme token(s) below AA`);',
    'console.log("Retrieved 5 auth records for review");',
  ];
  const wrong = prose.filter(c => ids(c).length > 0);
  if (wrong.length === 0) pass++;
  else { fail++; console.log(`FALSE+ log-rules-ignore-prose: ${wrong.length}`); }

  uniq('log-rules-catch-values');
  const real = [
    ['console.log("auth token=", token);', 'log-leak'],
    ['console.error("password:", password);', 'log-leak'],
    ['console.log(`user ${req.query.name}`);', 'log-inject'],
  ];
  const missed = real.filter(([c, id]) => !ids(c).includes(id));
  if (missed.length === 0) pass++;
  else { fail++; console.log(`MISS  log-rules-catch-values: ${missed.map(m => m[1])}`); }
})();

// --- log-leak anchors apply to every language, not just JS ---
// The first fix anchored only the console.* rule; Python, Go, Java, Ruby, C#
// and PHP kept matching bare substrings, so "auth completed" was CRITICAL.
(function loggingPrecisionAllLangs() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const leaks = (code, ext) => matchContent(code, 'lg.' + ext, pats)
    .filter(h => h.id === 'log-leak');

  uniq('log-leak-ignores-prose-all-langs');
  const prose = [
    ['logging.info("auth completed")', 'py'],
    ['logger.info("processed 5 tokens")', 'py'],
    ['log.Printf("user auth succeeded")', 'go'],
    ['logger.info("auth check passed")', 'java'],
    ['Rails.logger.info("token refresh done")', 'rb'],
    ['logger.Information("auth ok")', 'cs'],
    ['error_log("secret santa list built")', 'php'],
  ];
  const wrongL = prose.filter(([c, e]) => leaks(c, e).length > 0);
  if (wrongL.length === 0) pass++;
  else { fail++; console.log(`FALSE+ log-leak-ignores-prose-all-langs: ${wrongL.map(w => w[1])}`); }

  uniq('log-leak-catches-values-all-langs');
  const real = [
    ['logging.info("pw", password)', 'py'],
    ['log.Printf("%v", apiKey)', 'go'],
    ['logger.info("u", password)', 'java'],
    ['Rails.logger.debug(secret)', 'rb'],
    ['logger.Debug(apiKey)', 'cs'],
    ['error_log($password);', 'php'],
  ];
  const missedL = real.filter(([c, e]) => leaks(c, e).length === 0);
  if (missedL.length === 0) pass++;
  else { fail++; console.log(`MISS  log-leak-catches-values-all-langs: ${missedL.map(m => m[1])}`); }
})();

// --- API-9 flags deprecated versions, not the current one ---
// The rule matched /api/v1/, so every healthy versioned REST API was told
// its current version was deprecated.
(function api9Precision() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const hit = (code, ext) => matchContent(code, 'r.' + ext, pats)
    .filter(h => h.id === 'API-9').length > 0;

  uniq('api9-ignores-current-version');
  const current = [
    ["app.use('/api/v1', router);", 'js'],
    ['const u = "/api/v1/users";', 'js'],
    ['@app.route("/api/v1/x")', 'py'],
    ['fetch("/api/v2/items")', 'js'],
  ];
  const wrongA = current.filter(([c, e]) => hit(c, e));
  if (wrongA.length === 0) pass++;
  else { fail++; console.log(`FALSE+ api9-ignores-current-version: ${wrongA.length}`); }

  uniq('api9-catches-deprecated');
  const dep = [
    ["app.use('/api/legacy', router);", 'js'],
    ['const u = "/api/v0/users";', 'js'],
    ['@app.route("/api/beta/x")', 'py'],
    ['/** @deprecated */', 'js'],
  ];
  const missedA = dep.filter(([c, e]) => !hit(c, e));
  if (missedA.length === 0) pass++;
  else { fail++; console.log(`MISS  api9-catches-deprecated: ${missedA.length}`); }
})();

// --- alternation validator catches bare branches ---
// Four bugs came from a top-level `|` letting a branch match unanchored.
(function alternationValidator() {
  const sync = require('./sync.js');
  uniq('alternation-validator-detects-bare');
  const risky = ['auth', 'token', 'tmp_name'];
  const safe = ['DESCryptoServiceProvider', 'crypto/des', 'faye-websocket', '\\$_FILES\\['];
  const bad = risky.filter(b => !sync.isRiskyBareBranch(b));
  const wrong = safe.filter(b => sync.isRiskyBareBranch(b));
  if (bad.length === 0 && wrong.length === 0) pass++;
  else { fail++; console.log(`alternation-validator: missed=${bad} falsepos=${wrong}`); }

  uniq('alternation-splits-at-depth-zero');
  const b = sync.topLevelBranches('a\\s*\\(|(x|y)|[a|b]');
  if (b.length === 3) pass++;
  else { fail++; console.log(`alternation-splits-at-depth-zero: got ${b.length} want 3`); }
})();

// --- state follows the project, not the package ---
// Running the skill from a downstream repo wrote that project's findings into
// the installed skill's checks/findings.jsonl, so every other project's
// summary and report showed someone else's numbers.
(function stateFollowsProject() {
  const { statePath, writeState } = require('./config.js');
  const os = require('os');
  const cp = require('child_process');

  uniq('state-path-follows-cwd');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-state-'));
  const cwd0 = process.cwd();
  let inProject = '';
  try {
    cp.execFileSync('git', ['init', '-q'], { cwd: tmp, stdio: 'ignore' });
    process.chdir(tmp);
    inProject = statePath('findings.jsonl');
  } finally { process.chdir(cwd0); }
  // fs.realpath: macOS /tmp is a symlink to /private/tmp.
  const under = inProject.startsWith(fs.realpathSync(tmp)) || inProject.startsWith(tmp);
  if (under && !inProject.startsWith(DIR)) pass++;
  else { fail++; console.log(`state-path-follows-cwd: got ${inProject}`); }

  uniq('state-path-env-override-wins');
  process.env.SC_TEST_OVERRIDE = '/custom/f.jsonl';
  const ov = statePath('findings.jsonl', 'SC_TEST_OVERRIDE');
  delete process.env.SC_TEST_OVERRIDE;
  if (ov === '/custom/f.jsonl') pass++;
  else { fail++; console.log(`state-path-env-override-wins: got ${ov}`); }

  // writeState owns directory creation, so resolving a path never touches the
  // filesystem and a read-only project fails at the write, not at module load.
  uniq('state-write-creates-checks-dir');
  const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-state2-'));
  let resolvedOnly = false, wrote = false;
  try {
    process.chdir(tmp2);
    const f = statePath('findings.jsonl');
    resolvedOnly = !fs.existsSync(path.dirname(f));
    wrote = writeState(f, 'x\n') && fs.existsSync(f);
  } finally { process.chdir(cwd0); }
  if (resolvedOnly && wrote) pass++;
  else { fail++; console.log(`state-write-creates-checks-dir: resolveOnly=${resolvedOnly} wrote=${wrote}`); }

  // A project that cannot be written to must still report its findings.
  uniq('state-write-fails-soft-readonly');
  const tmp3 = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-state3-'));
  let soft = false;
  try {
    fs.chmodSync(tmp3, 0o500);
    const errs = [];
    const orig = console.error;
    console.error = (m) => errs.push(String(m));
    soft = writeState(path.join(tmp3, 'checks', 'f.jsonl'), 'x') === false;
    console.error = orig;
  } catch { soft = false; } finally {
    try { fs.chmodSync(tmp3, 0o700); } catch { /* ignore */ }
  }
  if (soft) pass++;
  else { fail++; console.log('state-write-fails-soft-readonly: threw instead of returning false'); }
  try { fs.rmSync(tmp3, { recursive: true, force: true }); } catch { /* ignore */ }

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
  try { fs.rmSync(tmp2, { recursive: true, force: true }); } catch { /* ignore */ }
})();

// --- no hardcoded test counts ---
// Four stale-number bugs this session all came from literals. The installer
// banners claimed 298 and 292 while the suite was at 469, and a banner that
// runs the tests but ignores their exit code says PASSED either way.
(function noHardcodedCounts() {
  uniq('installer-count-not-hardcoded');
  const offenders = [];
  for (const f of ['hooks/install.js', 'install.sh']) {
    const text = fs.readFileSync(path.join(DIR, f), 'utf8');
    for (const line of text.split('\n')) {
      if (/self-check|Self-check/i.test(line) && /\b\d{3}\b/.test(line)) offenders.push(`${f}: ${line.trim().slice(0, 50)}`);
    }
  }
  if (offenders.length === 0) pass++;
  else { fail++; console.log(`MISS  installer-count-not-hardcoded: ${offenders.join(' | ')}`); }

  // The banner must read the real result, not assume success.
  uniq('installer-checks-test-result');
  const js = fs.readFileSync(path.join(DIR, 'hooks', 'install.js'), 'utf8');
  const sh = fs.readFileSync(path.join(DIR, 'install.sh'), 'utf8');
  if (/pass=\(\\d\+\)/.test(js) && /fail=0/.test(sh)) pass++;
  else { fail++; console.log('MISS  installer-checks-test-result: banner does not inspect the outcome'); }
})();

// --- clean.js severity threshold and id aliases ---
(function cleanThreshold() {
  const CLEAN = path.join(DIR, 'hooks', 'clean.js');
  const dir = path.join(TMP, 'cleanthr');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const run = (name, body) => {
    const f = path.join(dir, name);
    fs.writeFileSync(f, body);
    return spawnSync('node', [CLEAN, f], { encoding: 'utf8', input: '' });
  };

  // A linter that fails a commit over a single-letter variable gets bypassed,
  // and then it catches nothing. failOn is 'high', so low must report not block.
  uniq('clean-low-reports-not-blocks');
  const low = run('low.js', 'let counter = 0;\n');
  if (low.status === 0 && /cc-/.test(low.stdout)) pass++;
  else { fail++; console.log(`MISS  clean-low-reports-not-blocks: status=${low.status}`); }

  uniq('clean-high-blocks');
  const high = run('high.js', 'try { x(); } catch (e) {}\n');
  if (high.status === 2) pass++;
  else { fail++; console.log(`MISS  clean-high-blocks: status=${high.status}`); }

  // scan.js and clean.js name the same defect differently; a reader writing
  // either spelling means the defect, so both must be honoured.
  uniq('clean-suppression-alias');
  const alias = run('alias.js', 'try { x(); } catch (e) {} // secure-coding-ignore: swallowed-exception -- deliberate\n');
  if (!/cc-swallowed/.test(alias.stdout)) pass++;
  else { fail++; console.log('MISS  clean-suppression-alias: scan.js id not accepted'); }

  // The repo's own deliberate suppressions must be respected.
  uniq('clean-repo-suppressions-honoured');
  const own = spawnSync('node', [CLEAN, path.join(DIR, 'hooks', 'scan.js'), path.join(DIR, 'hooks', 'install.js')],
    { encoding: 'utf8', input: '' });
  if (!/cc-swallowed/.test(own.stdout || '')) pass++;
  else { fail++; console.log('MISS  clean-repo-suppressions-honoured'); }
})();

// --- clean.js precision ---
// Clean-code rules describe executable code. Flagging a YAML version pin or a
// number inside a log message is noise, and noise is how a linter gets muted.
(function cleanPrecision() {
  const CLEAN = path.join(DIR, 'hooks', 'clean.js');
  const dir = path.join(TMP, 'cleanprec');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const lint = (name, body) => {
    const f = path.join(dir, name);
    fs.writeFileSync(f, body);
    return spawnSync('node', [CLEAN, f], { encoding: 'utf8', input: '' }).stdout || '';
  };

  uniq('clean-skips-config-formats');
  const body = 'description: Lints code against 14 universal Clean Code standards for you\n';
  const yaml = lint('hooks.yaml', body);
  const asJs = lint('same.js', body);
  if (!/cc-magic-number/.test(yaml) && /cc-magic-number/.test(asJs)) pass++;
  else { fail++; console.log('FALSE+ clean-skips-config-formats: extension is not being honoured'); }

  // A number in a message or a regex names nothing.
  uniq('magic-number-ignores-literals');
  const str = lint('msg.js', 'console.log("All 298 tests passed");\n');
  const rx = lint('rx.js', 'const re = /[^a]{0,40}/;\n');
  if (!/cc-magic-number/.test(str) && !/cc-magic-number/.test(rx)) pass++;
  else { fail++; console.log('FALSE+ magic-number-ignores-literals'); }

  // ...but a real constant in code must still be caught.
  uniq('magic-number-still-caught');
  if (/cc-magic-number/.test(lint('real.js', 'setTimeout(fn, 86400000);\n'))) pass++;
  else { fail++; console.log('MISS  magic-number-still-caught'); }

  // scan.js honours inline suppression; clean.js must agree, or a reviewed
  // exception is silenced by one tool and reported by the other.
  uniq('clean-honours-suppression');
  const sup = lint('sup.js', 'try { x(); } catch (e) {} // secure-coding-ignore: swallowed-error -- deliberate\n');
  const unsup = lint('unsup.js', 'try { x(); } catch (e) {}\n');
  if (!/cc-swallowed/.test(sup) && /cc-swallowed/.test(unsup)) pass++;
  else { fail++; console.log('MISS  clean-honours-suppression'); }

  uniq('clean-suppression-forms');
  const forms = [
    'try { x(); } catch (e) {} // secure-coding-ignore: cc-swallowed-error\n',
    'try { x(); } catch (e) {} // nosec: all\n',
  ];
  const leaked = forms.filter((b, i) => /cc-swallowed/.test(lint(`f${i}.js`, b)));
  if (leaked.length === 0) pass++;
  else { fail++; console.log(`MISS  clean-suppression-forms: ${leaked.length} not honoured`); }
})();

// --- clean.js robustness ---
(function cleanRobust() {
  const CLEAN = path.join(DIR, 'hooks', 'clean.js');
  const dir = path.join(TMP, 'cleanrb');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });

  // A statement continuing across lines is not followed by dead code. The
  // linter used to flag its own source on this.
  uniq('dead-code-multiline-return');
  const cont = path.join(dir, 'cont.js');
  fs.writeFileSync(cont, [
    'function a() {',
    '  return xs.map(x => {',
    '    return x * 2;',
    '  });',
    '}',
    'function b() {',
    '  return cond',
    '    ? left',
    '    : right;',
    '}',
    'function c() {',
    '  return JSON.stringify(items.map(h => ({',
    '    file: h.file,',
    '  })));',
    '}',
    '',
  ].join('\n'));
  const contOut = spawnSync('node', [CLEAN, cont], { encoding: 'utf8', input: '' }).stdout || '';
  if (!/cc-dead-code/.test(contOut)) pass++;
  else { fail++; console.log('FALSE+ dead-code-multiline-return'); }

  // ...but genuine dead code must still be reported.
  uniq('dead-code-still-caught');
  const real = path.join(dir, 'real.js');
  fs.writeFileSync(real, 'function f() {\n  return 1;\n  console.log("dead");\n}\n');
  if (/cc-dead-code/.test(spawnSync('node', [CLEAN, real], { encoding: 'utf8', input: '' }).stdout || '')) pass++;
  else { fail++; console.log('MISS  dead-code-still-caught'); }

  // The linter must not flag its own source.
  uniq('clean-self-lint-no-dead-code');
  const self = spawnSync('node', [CLEAN, CLEAN], { encoding: 'utf8', input: '' }).stdout || '';
  if (!/cc-dead-code/.test(self)) pass++;
  else { fail++; console.log('FALSE+ clean-self-lint-no-dead-code'); }

  // require() must not execute main() and read stdin.
  uniq('clean-requireable');
  const req = spawnSync('node', ['-e',
    `const m = require(${JSON.stringify(CLEAN)}); if (typeof m.checkFile !== 'function') process.exit(1);`],
    { encoding: 'utf8', input: '' });
  if (req.status === 0) pass++;
  else { fail++; console.log(`MISS  clean-requireable: ${(req.stderr || '').slice(0, 60)}`); }

  // ignorePaths must apply here too, or one tool skips what the other lints.
  uniq('clean-honours-ignorepaths');
  const all = spawnSync('node', [CLEAN, '--all'], { cwd: DIR, encoding: 'utf8', input: '' }).stdout || '';
  if (!/reports\/|hooks\/test\.js/.test(all)) pass++;
  else { fail++; console.log('MISS  clean-honours-ignorepaths: linted an ignored path'); }
})();

// --- gate relevance matches the scanner's sources ---
// scan.js gained request.json/get_json/values; if gate.js does not, staging a
// Flask handler that reads request.json skips the review it needs.
(function gateSourceParity() {
  const repo = path.join(TMP, 'srcparity');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.mkdirSync(repo, { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: repo });
  fs.writeFileSync(path.join(repo, 'api.py'), 'url = request.json.get("u")\nrequests.get(url)\n');
  spawnSync('git', ['add', '-A'], { cwd: repo });

  uniq('gate-sees-request-json');
  const r = spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--check'],
    { cwd: repo, encoding: 'utf8', env: { ...process.env, SECURE_CODING_GATE: path.join(TMP, 'sp.json') } });
  if (r.status === 2) pass++;
  else { fail++; console.log(`MISS  gate-sees-request-json: status=${r.status}`); }
})();

// --- clean.js CLI contract ---
// pass_filenames in .pre-commit-hooks.yaml means positional paths, and a
// linter that exits 0 on violations cannot block a commit. Both were broken,
// which made the shipped secure-coding-clean hook a no-op.
(function cleanCli() {
  const CLEAN = path.join(DIR, 'hooks', 'clean.js');
  const dir = path.join(TMP, 'cleancli');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const bad = path.join(dir, 'bad.js');
  const ok = path.join(dir, 'ok.js');
  fs.writeFileSync(bad, 'function f(a,b,c,d,e){ setTimeout(x, 86400000); }\ntry { g(); } catch (e) {}\n');
  fs.writeFileSync(ok, 'export const add = (a, b) => a + b;\n');
  const run = (...a) => spawnSync('node', [CLEAN, ...a], { encoding: 'utf8', input: '' });

  uniq('clean-positional-args');
  const pos = run(bad);
  if (pos.status === 2 && /Clean code issues/.test(pos.stdout)) pass++;
  else { fail++; console.log(`MISS  clean-positional-args: status=${pos.status}`); }

  uniq('clean-exits-nonzero');
  if (run('--file', bad).status === 2) pass++;
  else { fail++; console.log('MISS  clean-exits-nonzero: violations exited 0'); }

  uniq('clean-clean-file-passes');
  if (run(ok).status === 0) pass++;
  else { fail++; console.log('MISS  clean-clean-file-passes'); }

  uniq('clean-multi-file');
  const multi = run(bad, ok);
  if (multi.status === 2 && /bad\.js/.test(multi.stdout)) pass++;
  else { fail++; console.log(`MISS  clean-multi-file: status=${multi.status}`); }

  uniq('clean-json-valid');
  try {
    const parsed = JSON.parse(run('--json', bad).stdout);
    if (Array.isArray(parsed) && parsed.length > 0) pass++;
    else { fail++; console.log('MISS  clean-json-valid: empty'); }
  } catch { fail++; console.log('MISS  clean-json-valid: not JSON'); }
})();

// --- SARIF quality ---
(function sarifQuality() {
  const dir = path.join(TMP, 'sarifq');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, 'a.js');
  fs.writeFileSync(f, 'const x=1;\nconst y=2;\neval(req.body.z);\n');
  const state = path.join(TMP, 'sarifq.jsonl');
  const env = { ...process.env, SECURE_CODING_STATE: state, SECURE_CODING_REPORT: 'off' };
  spawnSync('node', [SCAN, '--files', f], { encoding: 'utf8', env });
  const out = spawnSync('node', [path.join(DIR, 'hooks', 'report.js'), '--sarif'], { encoding: 'utf8', env });

  uniq('sarif-quality');
  try {
    const d = JSON.parse(out.stdout);
    const driver = d.runs[0].tool.driver;
    const rule = driver.rules.find(r => r.id === 'eval');
    const res = d.runs[0].results.find(r => r.ruleId === 'eval');
    const pkg = JSON.parse(fs.readFileSync(path.join(DIR, 'package.json'), 'utf8')).version;
    const versionOk = driver.semanticVersion === pkg;
    // fullDescription must be remediation advice, not the matched line.
    const descOk = rule && !/^Line \d+:/.test(rule.fullDescription.text);
    const lineOk = res && res.locations[0].physicalLocation.region.startLine === 3;
    if (versionOk && descOk && lineOk) pass++;
    else { fail++; console.log(`MISS  sarif-quality: version=${versionOk} desc=${descOk} line=${lineOk}`); }
  } catch (e) { fail++; console.log(`MISS  sarif-quality: ${e.message}`); }
})();

// --- installed config matches the repo's own ---
(function configParity() {
  const repo = path.join(TMP, 'cfgrepo');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.mkdirSync(repo, { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: repo });
  spawnSync('node', [path.join(DIR, 'install.js'), '--target', repo, '--yes'],
    { env: { ...process.env, HOME: path.join(TMP, 'cfghome') }, encoding: 'utf8' });

  uniq('installed-config-parity');
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(repo, '.securecodingrc.json'), 'utf8'));
    if (cfg.taintTracking === true && (cfg.ignorePaths || []).includes('reports/**')) pass++;
    else { fail++; console.log('MISS  installed-config-parity: template drifted from the repo config'); }
  } catch { fail++; console.log('MISS  installed-config-parity: no config written'); }

  uniq('installed-pr-template');
  if (fs.existsSync(path.join(repo, '.github', 'pull_request_template.md'))) pass++;
  else { fail++; console.log('MISS  installed-pr-template'); }
})();

// --- taint: destructuring and Python request.json ---
// `const { file } = req.query` is the dominant idiom in modern JS/TS, and
// request.json is standard Flask/FastAPI. Both were invisible.
(function taintIdioms() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const ids = (code, ext) => matchContent(code, 'ti.' + ext, pats)
    .filter(h => h.id.startsWith('taint-')).map(h => h.id);

  const yes = (name, code, ext, id) => {
    uniq('taint-' + name);
    if (ids(code, ext).includes(id)) pass++;
    else { fail++; console.log(`MISS  taint-${name} (want ${id})`); }
  };
  const clean = (name, code, ext) => {
    uniq('taint-' + name);
    const got = ids(code, ext);
    if (got.length === 0) pass++;
    else { fail++; console.log(`FALSE+ taint-${name}: ${got}`); }
  };

  yes('destructured', 'const { file } = req.query;\nfs.readFileSync(file);', 'js', 'taint-path-traversal');
  yes('destructuredRenamed', 'const { file: f } = req.query;\nfs.readFileSync(f);', 'js', 'taint-path-traversal');
  yes('destructuredDefault', 'const { file = "a" } = req.query;\nfs.readFileSync(file);', 'js', 'taint-path-traversal');
  yes('destructuredMulti', 'const { a, url } = req.body;\nawait fetch(url);', 'js', 'taint-ssrf');
  yes('pyRequestJson', 'url = request.json.get("url")\nrequests.get(url)', 'py', 'taint-ssrf');
  yes('pyGetJson', 'url = request.get_json()["u"]\nrequests.get(url)', 'py', 'taint-ssrf');

  clean('destructureNonRequest', 'const { readFile } = require("fs");\nreadFile(p);', 'js');
  clean('destructureSanitized', 'const { file } = req.query;\nfs.readFileSync(path.basename(file));', 'js');
  clean('destructureParameterized', 'const { id } = req.params;\ndb.query("SELECT * WHERE i=?", [id]);', 'js');
})();

// --- placeholder secrets ---
// A high-entropy placeholder in .env.example is not a secret; flagging it
// critical teaches people to ignore the rule that finds the real ones.
(function placeholderSecrets() {
  const { loadPatterns, matchContent } = require('./scan.js');
  const pats = loadPatterns();
  const secretIds = (v) => matchContent(`api_key = "${v}"`, 'ph.py', pats)
    .filter(h => h.id.includes('secret')).map(h => h.id);

  uniq('placeholders-ignored');
  const placeholders = ['placeholder-secret-for-development-only', 'changeme-token-1234567890-test',
                        'your-api-key-goes-here-xxxx', 'REPLACE-WITH-YOUR-REAL-TOKEN-1234',
                        'EXAMPLE_TOKEN_ABCDEFGHIJKLMNOP'];
  const flagged = placeholders.filter(v => secretIds(v).length > 0);
  if (flagged.length === 0) pass++;
  else { fail++; console.log(`MISS  placeholders-ignored: flagged ${flagged.length}`); }

  uniq('real-secrets-still-flagged');
  const real = ['sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopQ', 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7'];
  const missed = real.filter(v => secretIds(v).length === 0);
  if (missed.length === 0) pass++;
  else { fail++; console.log(`MISS  real-secrets-still-flagged: missed ${missed.length}`); }
})();

// --- scan --all ---
(function scanAll() {
  const repo = path.join(TMP, 'allrepo');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.mkdirSync(repo, { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: repo });
  fs.writeFileSync(path.join(repo, 'bad.js'), 'eval(req.body.x);\n');
  fs.writeFileSync(path.join(repo, '.gitignore'), 'skipme.js\n');
  fs.writeFileSync(path.join(repo, 'skipme.js'), 'eval(req.body.y);\n');
  spawnSync('git', ['add', 'bad.js', '.gitignore'], { cwd: repo });

  uniq('scan-all-tracked-only');
  const r = spawnSync('node', [SCAN, '--all'], { cwd: repo, encoding: 'utf8',
    env: { ...process.env, SECURE_CODING_STATE: path.join(TMP, 'all.jsonl'), SECURE_CODING_REPORT: 'off' } });
  // finds the tracked file, ignores the gitignored one
  if (r.status === 2 && /bad\.js/.test(r.stdout) && !/skipme/.test(r.stdout)) pass++;
  else { fail++; console.log(`MISS  scan-all-tracked-only: status=${r.status}`); }
})();

// --- Done Gate over MCP ---
// An agent in a sandboxed IDE has no shell, so the whole loop has to be
// reachable as tools. These delegate to gate.js rather than reimplementing it.
(function gateOverMcp() {
  const GATE = path.join(TMP, 'mcpgate.json');
  try { fs.unlinkSync(GATE); } catch {}
  const call = (name, args) => {
    const req = [
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize',
        params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' } } }),
      JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: args } }),
    ].join('\n') + '\n';
    const r = spawnSync('node', [path.join(DIR, 'mcp', 'server.js')],
      { input: req, encoding: 'utf8', env: { ...process.env, SECURE_CODING_GATE: GATE } });
    try { return JSON.parse(r.stdout.trim().split('\n').pop()).result; } catch { return null; }
  };

  // Filler must be rejected through MCP exactly as it is on the CLI.
  uniq('mcp-gate-rejects-filler');
  const bad = call('record_security_decision', { question: 'ownership', answer: 'yes' });
  if (bad && bad.isError && /does not name a check/.test(bad.content[0].text)) pass++;
  else { fail++; console.log('MISS  mcp-gate-rejects-filler'); }

  uniq('mcp-gate-records');
  const ok = call('record_security_decision', { question: 'ownership', answer: 'scoped by an org_id predicate' });
  if (ok && !ok.isError && /recorded/.test(ok.content[0].text)) pass++;
  else { fail++; console.log('MISS  mcp-gate-records'); }

  uniq('mcp-gate-status-and-adr');
  const st = call('check_done_gate', {});
  const adr = call('check_done_gate', { format: 'adr' });
  if (st && /Done Gate/.test(st.content[0].text) &&
      adr && /### ADR/.test(adr.content[0].text) && /org_id predicate/.test(adr.content[0].text)) pass++;
  else { fail++; console.log('MISS  mcp-gate-status-and-adr'); }
})();

// --- PR template carries the gate questions ---
(function prTemplate() {
  uniq('pr-template-questions');
  const f = path.join(DIR, '.github', 'pull_request_template.md');
  const text = fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : '';
  const qs = ['Ownership', 'Authorization', 'Taint', 'Failure direction'];
  const absent = qs.filter(q => !text.includes(q));
  if (text && absent.length === 0) pass++;
  else { fail++; console.log(`MISS  pr-template-questions: ${absent.join(', ') || 'file missing'}`); }
})();

// --- git worktrees ---
// In a worktree (and a submodule) .git is a FILE pointing elsewhere, so
// path.join(top, '.git', ...) crashes: EEXIST in gate.js, ENOTDIR in
// install.js. git rev-parse resolves the real directory in every layout.
(function worktrees() {
  const base = path.join(TMP, 'wtbase');
  fs.rmSync(base, { recursive: true, force: true });
  fs.mkdirSync(base, { recursive: true });
  const git = (cwd, ...a) => spawnSync('git', a, { cwd, encoding: 'utf8' });
  git(base, 'init', '-q');
  fs.writeFileSync(path.join(base, 'i.txt'), 'init\n');
  git(base, 'add', 'i.txt');
  git(base, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'init');
  const wt = path.join(base, 'wt');
  git(base, 'worktree', 'add', '-q', wt, '-b', 'br');

  uniq('worktree-is-a-file');
  if (fs.existsSync(path.join(wt, '.git')) && fs.statSync(path.join(wt, '.git')).isFile()) pass++;
  else { fail++; console.log('MISS  worktree-is-a-file: fixture did not produce a worktree'); }

  // gate.js must record without crashing, into the worktree's own git dir.
  uniq('worktree-gate-records');
  const g = spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'),
    '--answer', 'ownership', 'scoped by an org predicate'], { cwd: wt, encoding: 'utf8' });
  if (g.status === 0 && !/EEXIST/.test(g.stderr)) pass++;
  else { fail++; console.log(`MISS  worktree-gate-records: ${(g.stderr || '').slice(0, 60)}`); }

  // install.js must find the shared hooks dir rather than <wt>/.git/hooks.
  uniq('worktree-install-hooks');
  const i = spawnSync('node', [path.join(DIR, 'install.js'), '--target', wt, '--yes'],
    { env: { ...process.env, HOME: path.join(TMP, 'wthome') }, encoding: 'utf8' });
  const hooks = spawnSync('git', ['rev-parse', '--git-path', 'hooks'], { cwd: wt, encoding: 'utf8' }).stdout.trim();
  const installed = hooks && fs.existsSync(path.resolve(wt, hooks, 'pre-commit'));
  if (installed && !/ENOTDIR/.test(i.stderr || '')) pass++;
  else { fail++; console.log(`MISS  worktree-install-hooks: ${(i.stderr || '').slice(0, 60)}`); }
})();

// --- ADR output ---
(function adrOutput() {
  const GATE = path.join(TMP, 'adr-gate.json');
  const run = (...a) => spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), ...a],
    { env: { ...process.env, SECURE_CODING_GATE: GATE }, encoding: 'utf8' });
  try { fs.unlinkSync(GATE); } catch {}

  // Nothing recorded is not an ADR; say so rather than print an empty table.
  uniq('adr-empty-fails');
  if (run('--adr').status === 2) pass++;
  else { fail++; console.log('MISS  adr-empty-fails'); }

  uniq('adr-renders-answers');
  run('--answer', 'ownership', 'scoped by org_id predicate in the query');
  const out = run('--adr');
  if (out.status === 0 && /org_id predicate/.test(out.stdout) && /_unanswered_/.test(out.stdout)) pass++;
  else { fail++; console.log(`MISS  adr-renders-answers: status=${out.status}`); }

  // A pipe in an answer must not break the markdown table.
  uniq('adr-escapes-pipes');
  run('--answer', 'authorization', 'requireAuth | requireAdmin on the router');
  const piped = run('--adr');
  const row = piped.stdout.split('\n').find(l => l.startsWith('| authorization'));
  if (row && row.includes('\\|') && !/[^\\]\|.*\|.*[^\\]\|.*\|/.test(row)) pass++;
  else { fail++; console.log(`MISS  adr-escapes-pipes: ${row}`); }
})();

// --- frontier surfaces: CLI and MCP ---
(function frontierSurfaces() {
  const { FRONTIERS, DOMAINS, forDomain, render } = require('./frontiers.js');

  uniq('frontiers-five');
  if (FRONTIERS.length === 5) pass++;
  else { fail++; console.log(`MISS  frontiers-five: ${FRONTIERS.length}`); }

  // Four of the five must pre-answer a Done Gate question, or the loop is open.
  uniq('frontiers-map-to-gate');
  const gates = FRONTIERS.map(f => f.gate).filter(Boolean).sort();
  const want = ['authorization', 'failure-direction', 'ownership', 'taint'];
  if (JSON.stringify(gates) === JSON.stringify(want)) pass++;
  else { fail++; console.log(`MISS  frontiers-map-to-gate: ${gates}`); }

  uniq('frontiers-domain-filter');
  const llm = forDomain('llm').map(f => f.id);
  if (llm.includes('agency') && !llm.includes('tenancy') && forDomain('all').length === 5) pass++;
  else { fail++; console.log(`MISS  frontiers-domain-filter: ${llm}`); }

  uniq('gate-grill-cli');
  const g = spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--grill', 'api'], { encoding: 'utf8' });
  const bad = spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--grill', 'nope'], { encoding: 'utf8' });
  if (g.status === 0 && /Q1/.test(g.stdout) && bad.status === 64) pass++;
  else { fail++; console.log(`MISS  gate-grill-cli: ok=${g.status} bad=${bad.status}`); }

  // The MCP tool must return the same text as the CLI — one source, two doors.
  uniq('mcp-frontier-tool');
  const req = [
    JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '1' } } }),
    JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call',
      params: { name: 'get_security_frontier', arguments: { domain: 'storage' } } }),
  ].join('\n') + '\n';
  const m = spawnSync('node', [path.join(DIR, 'mcp', 'server.js')], { input: req, encoding: 'utf8' });
  let text = '';
  try {
    const last = m.stdout.trim().split('\n').pop();
    text = JSON.parse(last).result.content[0].text;
  } catch {}
  if (text && text === render('storage')) pass++;
  else { fail++; console.log('MISS  mcp-frontier-tool: output missing or differs from the CLI'); }
})();

// --- secure grilling is reachable and wired in ---
// The gate catches a missing ownership check at commit time; grilling is what
// stops it being written. If the routing or the agent rules lose the reference,
// the agent never asks and the loop is open again.
(function grilling() {
  uniq('grilling-doc-exists');
  const doc = path.join(DIR, 'checks', 'secure-grilling.md');
  if (fs.existsSync(doc)) pass++;
  else { fail++; console.log('MISS  grilling-doc-exists'); }

  // Every frontier must name the gate question it pre-answers, or the loop
  // does not actually close.
  uniq('grilling-maps-to-gate');
  const text = fs.existsSync(doc) ? fs.readFileSync(doc, 'utf8') : '';
  const qs = ['ownership', 'authorization', 'taint', 'failure-direction'];
  const absent = qs.filter(q => !text.includes(`gate: ${q}`));
  if (absent.length === 0) pass++;
  else { fail++; console.log(`MISS  grilling-maps-to-gate: ${absent.join(', ')}`); }

  uniq('grilling-in-skill-md');
  const skill = fs.readFileSync(path.join(DIR, 'SKILL.md'), 'utf8');
  if (skill.includes('secure-grilling.md') && /Step 0/.test(skill)) pass++;
  else { fail++; console.log('MISS  grilling-in-skill-md'); }

  // The agent rule files are what actually make an agent do this.
  uniq('grilling-in-agent-rules');
  const rules = ['AGENTS.md', '.clinerules', '.windsurfrules',
                 path.join('.cursor', 'rules', 'secure-coding.mdc')];
  const missing = rules.filter(r => !fs.readFileSync(path.join(DIR, r), 'utf8').includes('secure-grilling'));
  if (missing.length === 0) pass++;
  else { fail++; console.log(`MISS  grilling-in-agent-rules: ${missing.join(', ')}`); }
})();

// --- second-review findings ---
(function secondReview() {
  const repo = path.join(TMP, 'srrepo');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.mkdirSync(path.join(repo, 'src'), { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: repo });
  const gateAt = (cwd, state) => spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--check'],
    { cwd, encoding: 'utf8', env: { ...process.env, SECURE_CODING_GATE: path.join(TMP, state) } });

  // An idle tree has nothing to review; blocking there made the gate fire in
  // the state it is most often run in.
  uniq('gate-idle-tree-passes');
  if (gateAt(repo, 'sr1.json').status === 0) pass++;
  else { fail++; console.log('MISS  gate-idle-tree-passes: blocked with nothing staged'); }

  // git prints repo-root-relative paths; resolving against cwd made a run from
  // a subdirectory see no files at all.
  fs.writeFileSync(path.join(repo, 'src', 'api.js'), 'eval(req.body.x);\n');
  spawnSync('git', ['add', '-A'], { cwd: repo });

  uniq('scan-staged-from-subdir');
  const scanAt = (cwd, state) => spawnSync('node', [SCAN, '--staged'], {
    cwd, encoding: 'utf8',
    env: { ...process.env, SECURE_CODING_STATE: path.join(TMP, state), SECURE_CODING_REPORT: 'off' } });
  const root = scanAt(repo, 'sr2.jsonl');
  const sub = scanAt(path.join(repo, 'src'), 'sr3.jsonl');
  if (root.status === 2 && sub.status === 2 && /eval/.test(sub.stdout)) pass++;
  else { fail++; console.log(`MISS  scan-staged-from-subdir: root=${root.status} sub=${sub.status}`); }

  uniq('gate-from-subdir');
  if (gateAt(path.join(repo, 'src'), 'sr4.json').status === 2) pass++;
  else { fail++; console.log('MISS  gate-from-subdir: did not see the staged route'); }

  // The chained hook must not embed an absolute path, or moving the repo
  // breaks it.
  uniq('hook-chain-relative');
  const hp = path.join(repo, '.git', 'hooks', 'pre-commit');
  fs.writeFileSync(hp, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  spawnSync('node', [path.join(DIR, 'install.js'), '--target', repo, '--yes'],
    { env: { ...process.env, HOME: path.join(TMP, 'srhome') }, encoding: 'utf8' });
  const hook = fs.readFileSync(hp, 'utf8');
  if (hook.includes('PREV_HOOK') && !hook.includes(repo)) pass++;
  else { fail++; console.log('MISS  hook-chain-relative: absolute path embedded'); }
})();

// --- review findings: state isolation, staged blobs, hook chaining ---
(function reviewFixes() {
  const repo = path.join(TMP, 'revrepo');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.mkdirSync(repo, { recursive: true });
  const git = (...a) => spawnSync('git', a, { cwd: repo, encoding: 'utf8' });
  git('init', '-q');

  // --staged must judge the index, not the working tree. An unstaged fix must
  // not hide a staged flaw, and an unstaged flaw must not fail a clean commit.
  const scanStaged = (state) => spawnSync('node', [SCAN, '--staged'], {
    cwd: repo, encoding: 'utf8',
    env: { ...process.env, SECURE_CODING_STATE: path.join(TMP, state), SECURE_CODING_REPORT: 'off' },
  });

  uniq('staged-reads-index-clean');
  fs.writeFileSync(path.join(repo, 'a.js'), 'const x = 1;\n');
  git('add', 'a.js');
  fs.writeFileSync(path.join(repo, 'a.js'), 'eval(req.body.x);\n');  // dirty, unstaged
  if (scanStaged('s1.jsonl').status === 0) pass++;
  else { fail++; console.log('MISS  staged-reads-index-clean: flagged an unstaged change'); }

  uniq('staged-reads-index-dirty');
  fs.writeFileSync(path.join(repo, 'b.js'), 'eval(req.body.x);\n');
  git('add', 'b.js');
  fs.writeFileSync(path.join(repo, 'b.js'), 'const y = 2;\n');       // fixed only in the tree
  if (scanStaged('s2.jsonl').status === 2) pass++;
  else { fail++; console.log('MISS  staged-reads-index-dirty: missed a staged flaw'); }

  // Installing must not destroy an existing pre-commit hook.
  uniq('hook-chaining-preserves');
  const hookRepo = path.join(TMP, 'hookrepo');
  fs.rmSync(hookRepo, { recursive: true, force: true });
  fs.mkdirSync(hookRepo, { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: hookRepo });
  const hookPath = path.join(hookRepo, '.git', 'hooks', 'pre-commit');
  fs.writeFileSync(hookPath, '#!/bin/sh\necho "husky here"\nexit 0\n', { mode: 0o755 });
  spawnSync('node', [path.join(DIR, 'install.js'), '--target', hookRepo, '--yes'],
    { env: { ...process.env, HOME: path.join(TMP, 'hookhome') }, encoding: 'utf8' });
  const backup = `${hookPath}.pre-secure-coding`;
  const chained = fs.existsSync(hookPath) && fs.readFileSync(hookPath, 'utf8').includes('pre-secure-coding');
  if (fs.existsSync(backup) && chained) pass++;
  else { fail++; console.log('MISS  hook-chaining-preserves: existing hook was clobbered'); }
})();

// --- --global actually installs the skill ---
// The generated git hooks fall back to $HOME/.secure-coding/hooks/*.js. That
// directory used to be created empty, so after an npx install every hook was a
// silent no-op — a commit with eval() in it sailed through.
(function globalInstall() {
  const home = path.join(TMP, 'globalhome');
  const proj = path.join(TMP, 'globalproj');
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(proj, { recursive: true, force: true });
  fs.mkdirSync(proj, { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: proj });
  spawnSync('node', [path.join(DIR, 'install.js'), '--global', '--target', proj, '--yes'],
    { env: { ...process.env, HOME: home }, encoding: 'utf8' });

  uniq('global-copies-skill');
  const needed = ['hooks/scan.js', 'hooks/gate.js', 'patterns', 'checks'];
  const absent = needed.filter(f => !fs.existsSync(path.join(home, '.secure-coding', f)));
  if (absent.length === 0) pass++;
  else { fail++; console.log(`MISS  global-copies-skill: ${absent.join(', ')} not copied`); }

  // The fallback must produce a hook that actually blocks.
  uniq('global-hook-blocks');
  fs.writeFileSync(path.join(proj, 'bad.js'), 'eval(req.body.x);\n');
  spawnSync('git', ['add', '-A'], { cwd: proj });
  const c = spawnSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-m', 't'],
    { cwd: proj, env: { ...process.env, HOME: home }, encoding: 'utf8' });
  if (c.status !== 0) pass++;
  else { fail++; console.log('MISS  global-hook-blocks: eval() was committed'); }
})();

// --- PostToolUse auto-configuration ---
// Write-time scanning is the trigger that does not need git. install.js used
// to only print a hint, so most installs never had it.
(function postToolUse() {
  const home = path.join(TMP, 'fakehome');
  const proj = path.join(TMP, 'ptuproj');
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(proj, { recursive: true, force: true });
  fs.mkdirSync(proj, { recursive: true });
  spawnSync('git', ['init', '-q'], { cwd: proj });
  const install = () => spawnSync('node', [path.join(DIR, 'install.js'),
    '--target', proj, '--agent', 'claude', '--yes'],
    { env: { ...process.env, HOME: home }, encoding: 'utf8' });
  const settingsPath = path.join(home, '.claude', 'settings.json');

  uniq('ptu-configured');
  install();
  let ok = false;
  try {
    const cfg = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    ok = JSON.stringify(cfg.hooks.PostToolUse).includes('scan.js');
  } catch {}
  if (ok) pass++;
  else { fail++; console.log('MISS  ptu-configured: PostToolUse hook not written'); }

  // Running install twice must not stack duplicate hooks.
  uniq('ptu-idempotent');
  install();
  let count = 0;
  try { count = JSON.parse(fs.readFileSync(settingsPath, 'utf8')).hooks.PostToolUse.length; } catch {}
  if (count === 1) pass++;
  else { fail++; console.log(`MISS  ptu-idempotent: ${count} entries after two installs`); }

  // Existing settings must survive untouched.
  uniq('ptu-preserves-settings');
  fs.rmSync(home, { recursive: true, force: true });
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify({ model: 'opus', hooks: { PreToolUse: [{ matcher: 'Bash' }] } }));
  install();
  let kept = false;
  try {
    const cfg = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    kept = cfg.model === 'opus' && !!cfg.hooks.PreToolUse && !!cfg.hooks.PostToolUse;
  } catch {}
  if (kept) pass++;
  else { fail++; console.log('MISS  ptu-preserves-settings: existing keys lost'); }

  // A malformed settings.json must be left alone, not overwritten.
  uniq('ptu-safe-on-bad-json');
  fs.writeFileSync(settingsPath, '{ "model": "opus", BROKEN');
  const before = fs.readFileSync(settingsPath, 'utf8');
  install();
  if (fs.readFileSync(settingsPath, 'utf8') === before) pass++;
  else { fail++; console.log('MISS  ptu-safe-on-bad-json: clobbered an unparseable file'); }
})();

// --- ignorePaths is enforced ---
// It was documented in .securecodingrc.json but scan.js never read it, so
// fixture directories were scanned anyway.
(function ignorePaths() {
  const { scanSingleFile, loadPatterns } = require('./scan.js');
  uniq('ignore-paths-enforced');
  // hooks/test.js is listed in ignorePaths and is full of deliberate fixtures.
  const self = scanSingleFile(path.join(DIR, 'hooks', 'test.js'), loadPatterns());
  // A file that is not ignored must still report.
  const live = path.join(TMP, 'notignored.js');
  fs.writeFileSync(live, 'eval(req.body.x);\n');
  const other = scanSingleFile(live, loadPatterns());
  if (self.length === 0 && other.length > 0) pass++;
  else { fail++; console.log(`MISS  ignore-paths-enforced: ignored=${self.length} live=${other.length}`); }
})();

// --- gate relevance ---
// A gate that fires on every commit teaches people to bypass the hook, which
// would disable the scanner too. It must ask only when the staged code
// contains what the four questions are about.
(function gateRelevance() {
  const repo = path.join(TMP, 'relrepo');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.mkdirSync(repo, { recursive: true });
  const git = (...a) => spawnSync('git', a, { cwd: repo, encoding: 'utf8' });
  git('init', '-q');
  const GATE = path.join(TMP, 'rel-gate.json');
  const check = () => {
    try { fs.unlinkSync(GATE); } catch {}
    git('add', '-A');
    return spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--check'],
      { cwd: repo, env: { ...process.env, SECURE_CODING_GATE: GATE }, encoding: 'utf8' });
  };
  const write = (name, body) => {
    for (const f of fs.readdirSync(repo)) if (f !== '.git') fs.rmSync(path.join(repo, f), { recursive: true, force: true });
    fs.writeFileSync(path.join(repo, name), body);
  };

  // Changes that cannot answer the questions must pass straight through.
  const skips = [
    ['README.md', '# docs\n'],
    ['cfg.json', '{"a":1}\n'],
    ['math.js', 'export function add(a,b){return a+b}\n'],
    ['sum.test.js', 'test("adds", () => expect(add(1,2)).toBe(3));\n'],
  ];
  uniq('gate-skips-irrelevant');
  const wrongly = skips.filter(([n, b]) => { write(n, b); return check().status !== 0; });
  if (wrongly.length === 0) pass++;
  else { fail++; console.log(`MISS  gate-skips-irrelevant: required review for ${wrongly.map(w => w[0])}`); }

  // Request handling, data access and authorization must all trigger it.
  const requires = [
    ['api.js', "app.get('/u/:id', (req,res) => res.json(db.findById(req.params.id)));\n"],
    ['view.py', '@app.route("/x")\ndef h():\n    return q(request.args["a"])\n'],
    ['repo.ts', 'const u = await db.user.findFirst({where:{id}});\n'],
    ['authz.js', 'if (!isAdmin(user)) return res.sendStatus(403);\n'],
  ];
  uniq('gate-requires-relevant');
  const missed = requires.filter(([n, b]) => { write(n, b); return check().status === 0; });
  if (missed.length === 0) pass++;
  else { fail++; console.log(`MISS  gate-requires-relevant: skipped ${missed.map(m => m[0])}`); }

  // A docs change alongside a route still needs the review.
  uniq('gate-mixed-commit');
  for (const f of fs.readdirSync(repo)) if (f !== '.git') fs.rmSync(path.join(repo, f), { recursive: true, force: true });
  fs.writeFileSync(path.join(repo, 'README.md'), '# hi\n');
  fs.writeFileSync(path.join(repo, 'pay.js'), "app.post('/pay', (req,res) => charge(req.body.amt));\n");
  const mixed = check();
  if (mixed.status === 2 && /pay\.js/.test(mixed.stderr) && !/README/.test(mixed.stderr)) pass++;
  else { fail++; console.log(`MISS  gate-mixed-commit: status=${mixed.status}`); }

  // --all forces the review for a deliberate audit.
  uniq('gate-all-forces');
  write('README.md', '# docs\n');
  try { fs.unlinkSync(GATE); } catch {}
  git('add', '-A');
  const forced = spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--check', '--all'],
    { cwd: repo, env: { ...process.env, SECURE_CODING_GATE: GATE }, encoding: 'utf8' });
  if (forced.status === 2) pass++;
  else { fail++; console.log(`MISS  gate-all-forces: status=${forced.status}`); }

  // Answers belong to the repo, not the skill install.
  uniq('gate-state-per-repo');
  const st = spawnSync('node', [path.join(DIR, 'hooks', 'gate.js'), '--answer', 'ownership', 'scoped by a userId predicate'],
    { cwd: repo, env: { ...process.env, SECURE_CODING_GATE: '' }, encoding: 'utf8' });
  if (st.status === 0 && fs.existsSync(path.join(repo, '.git', 'secure-coding-gate.json'))) pass++;
  else { fail++; console.log('MISS  gate-state-per-repo: answers not stored in the repo'); }
})();

// --- template roster & README matrix ---
// sync.js validates the templates that exist; it could not see that shell.md
// was absent while the README's matrix claimed a Sh column.
(function templateRoster() {
  const dir = path.join(DIR, 'templates');
  const LANGS = ['c', 'csharp', 'go', 'java', 'javascript', 'kotlin', 'php',
                 'python', 'ruby', 'rust', 'shell', 'swift', 'typescript'];

  uniq('template-roster');
  const absent = LANGS.filter(l => !fs.existsSync(path.join(dir, `${l}.md`)));
  const extra = fs.readdirSync(dir).filter(f => f.endsWith('.md'))
    .map(f => f.replace('.md', '')).filter(l => !LANGS.includes(l));
  if (absent.length === 0 && extra.length === 0) pass++;
  else { fail++; console.log(`MISS  template-roster: absent=[${absent}] undocumented=[${extra}]`); }

  // Every language the README's matrix names must have a template.
  uniq('template-readme-matrix');
  const readme = fs.readFileSync(path.join(DIR, 'README.md'), 'utf8');
  const header = (readme.match(/^\| # \| Security Control \|([^\n]*)\|$/m) || [])[1] || '';
  const cols = header.split('|').map(c => c.trim()).filter(Boolean);
  if (cols.length === LANGS.length) pass++;
  else { fail++; console.log(`MISS  template-readme-matrix: ${cols.length} columns for ${LANGS.length} templates (${cols})`); }

  // Sections a language genuinely cannot have are declared; everything else
  // must be present, so a stripped template fails loudly.
  uniq('template-core-sections');
  const CORE = ['password hashing', 'secure random', 'constant-time', 'input validation',
                'secrets', 'error handling', 'logging', 'file permission'];
  const short = [];
  for (const l of LANGS) {
    const text = fs.readFileSync(path.join(dir, `${l}.md`), 'utf8').toLowerCase();
    const miss = CORE.filter(c => !text.includes(c));
    if (miss.length) short.push(`${l}:${miss.join('/')}`);
  }
  if (short.length === 0) pass++;
  else { fail++; console.log(`MISS  template-core-sections: ${short.join(' ')}`); }
})();

// --- SKILL.md references resolve ---
// A renamed or missing checks/ file would silently send the agent nowhere.
(function skillLinks() {
  uniq('skill-check-links');
  const skill = fs.readFileSync(path.join(DIR, 'SKILL.md'), 'utf8');
  const refs = [...new Set((skill.match(/checks\/[a-z0-9-]+\.md/g) || []))];
  const missing = refs.filter(r => !fs.existsSync(path.join(DIR, r)));
  if (refs.length > 0 && missing.length === 0) pass++;
  else { fail++; console.log(`LINKS unresolved in SKILL.md: ${missing.join(', ') || '(no refs found)'}`); }
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



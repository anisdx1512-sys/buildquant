/* ════════════════════════════════════════════
   CLOUDFLARE WORKERS — BuildQuant v4
   API Backend : Cloudflare Workers + D1
   ⚠ remplacez YOUR_SUBDOMAIN par votre sous-domaine réel
════════════════════════════════════════════ */
var API = '/api';

var currentUser  = null;
var accessToken  = null;
var editingIndex = -1;   // ← déclaré UNE SEULE FOIS (bug corrigé)

/* ════════════════════════════════════════════
   HEADERS — Cloudflare (plus d'apikey Supabase)
════════════════════════════════════════════ */
function authHeaders(token) {
  var h = { 'Content-Type': 'application/json' };
  if (token) h['Authorization'] = 'Bearer ' + token;
  return h;
}

/* ════════════════════════════════════════════
   LOCAL AUTH — mode hors ligne / offline fallback
   Comptes stockés chiffrés dans localStorage
════════════════════════════════════════════ */
async function sha256hex(str) {
  var buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str + 'BQ_LOCAL_SALT_2024'));
  return Array.from(new Uint8Array(buf)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}

async function localRegister(email, pw, prenom) {
  var accounts = JSON.parse(localStorage.getItem('bq_accounts') || '{}');
  if (accounts[email]) return { error: 'Email déjà utilisé (compte local)' };
  var hash = await sha256hex(pw);
  var userId = 'local_' + Date.now();
  accounts[email] = { id: userId, email: email, prenom: prenom, hash: hash };
  localStorage.setItem('bq_accounts', JSON.stringify(accounts));
  return { access_token: 'local_' + userId, user: { id: userId, email: email, user_metadata: { prenom: prenom } } };
}

async function localLogin(email, pw) {
  var accounts = JSON.parse(localStorage.getItem('bq_accounts') || '{}');
  if (!accounts[email]) return { error: 'Aucun compte local pour cet email' };
  var hash = await sha256hex(pw);
  if (accounts[email].hash !== hash) return { error: 'Mot de passe incorrect' };
  var a = accounts[email];
  return { access_token: 'local_' + a.id, user: { id: a.id, email: email, user_metadata: { prenom: a.prenom } } };
}

function isCloudMode() {
  return !!(currentUser && accessToken && typeof accessToken === 'string' && !accessToken.startsWith('local_'));
}

/* ════════════════════════════════════════════
   AUTH FUNCTIONS — Workers endpoints
════════════════════════════════════════════ */
async function supaRegister(email, pw, prenom) {
  var r = await fetch(API + '/auth/register', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ email: email, password: pw, prenom: prenom })
  });
  return await r.json();
}

async function supaLogin(email, pw) {
  var r = await fetch(API + '/auth/login', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ email: email, password: pw })
  });
  return await r.json();
}

async function supaGetUser(token) {
  var r = await fetch(API + '/auth/user', {
    headers: authHeaders(token)
  });
  return await r.json();
}

/* ════════════════════════════════════════════
   DB FUNCTIONS — Workers endpoints
════════════════════════════════════════════ */
async function supaInsertProject(data) {
  var r = await fetch(API + '/projects', {
    method: 'POST',
    headers: authHeaders(accessToken),
    body: JSON.stringify(data)
  });
  return r.ok;
}

async function supaGetProjects() {
  var r = await fetch(API + '/projects', {
    headers: authHeaders(accessToken)
  });
  if (!r.ok) return null;
  return await r.json();
}

async function supaDeleteProject(id) {
  var r = await fetch(API + '/projects/' + id, {
    method: 'DELETE',
    headers: authHeaders(accessToken)
  });
  return r.ok;
}

/* ════════════════════════════════════════════
   SESSION STORAGE
════════════════════════════════════════════ */
function saveSession(user, token) {
  localStorage.setItem('bq_session', JSON.stringify({ user: user, token: token, ts: Date.now() }));
}
function loadSession() {
  try {
    var s = JSON.parse(localStorage.getItem('bq_session') || 'null');
    if (!s) return null;
    if (Date.now() - s.ts > 7 * 24 * 3600 * 1000) { localStorage.removeItem('bq_session'); return null; }
    return s;
  } catch(e) { return null; }
}
function clearSession() { localStorage.removeItem('bq_session'); }

/* ════════════════════════════════════════════
   AUTH OVERLAY
════════════════════════════════════════════ */
function showAuthOverlay() { document.getElementById('auth-overlay').style.display = 'flex'; }
function hideAuthOverlay() { document.getElementById('auth-overlay').style.display = 'none'; }

async function doLogin() {
  var email = document.getElementById('auth-email').value.trim();
  var pw    = document.getElementById('auth-pw').value;
  var errEl = document.getElementById('auth-error');
  if (!email || !pw) { errEl.textContent = 'Remplissez tous les champs.'; errEl.style.display = 'block'; return; }
  errEl.style.display = 'none';
  document.getElementById('auth-login-btn').textContent = 'Connexion...';
  try {
    var r = await supaLogin(email, pw);
    document.getElementById('auth-login-btn').textContent = 'Se connecter';
    if (r.error || !r.access_token) {
      errEl.textContent = r.error || 'Email ou mot de passe incorrect.';
      errEl.style.display = 'block'; return;
    }
    accessToken = r.access_token;
    currentUser = r.user;
    saveSession(currentUser, accessToken);
    onLogin();
  } catch(e) {
    document.getElementById('auth-login-btn').textContent = 'Se connecter';
    var lr = await localLogin(email, pw);
    if (!lr.error) {
      accessToken = lr.access_token;
      currentUser = lr.user;
      saveSession(currentUser, accessToken);
      notify('📴 Mode hors ligne — compte local');
      onLogin();
    } else {
      errEl.textContent = 'Hors ligne. ' + (lr.error === 'Aucun compte local pour cet email' ? 'Aucun compte local trouvé — créez un compte d\'abord.' : lr.error);
      errEl.style.display = 'block';
    }
  }
}

async function doRegister() {
  var email  = document.getElementById('auth-email-r').value.trim();
  var pw     = document.getElementById('auth-pw-r').value;
  var prenom = document.getElementById('auth-prenom').value.trim();
  var errEl  = document.getElementById('auth-error-r');
  if (!email || !pw || !prenom) { errEl.textContent = 'Remplissez tous les champs.'; errEl.style.display = 'block'; return; }
  if (pw.length < 8) { errEl.textContent = 'Mot de passe min. 8 caractères.'; errEl.style.display = 'block'; return; }
  errEl.style.display = 'none';
  document.getElementById('auth-reg-btn').textContent = 'Création...';
  try {
    var r = await supaRegister(email, pw, prenom);
    document.getElementById('auth-reg-btn').textContent = 'Créer mon compte gratuit';
    if (r.error) { errEl.textContent = r.error; errEl.style.display = 'block'; return; }
    if (r.access_token) {
      accessToken = r.access_token;
      currentUser = r.user;
      saveSession(currentUser, accessToken);
      onLogin();
    } else {
      notify('📧 Compte créé — connectez-vous');
      switchAuthTab('login');
    }
  } catch(e) {
    document.getElementById('auth-reg-btn').textContent = 'Créer mon compte gratuit';
    var lr = await localRegister(email, pw, prenom);
    if (!lr.error) {
      accessToken = lr.access_token;
      currentUser = lr.user;
      saveSession(currentUser, accessToken);
      notify('📴 Compte créé en mode hors ligne');
      onLogin();
    } else {
      errEl.textContent = 'Hors ligne. ' + lr.error;
      errEl.style.display = 'block';
    }
  }
}

/* ── LOGOUT — corrigé : appelle Workers endpoint ── */
async function doLogout() {
  try {
    if (isCloudMode()) {
      await fetch(API + '/auth/logout', {
        method: 'POST',
        headers: authHeaders(accessToken)
      });
    }
  } catch(e) {}
  currentUser  = null;
  accessToken  = null;
  projects     = [];
  editingIndex = -1;
  clearSession();
  document.getElementById('nb-projects').textContent = '0';
  updateSidebar();
  showAuthOverlay();
  notify('Déconnecté');
}

function loginLocal() {
  currentUser = { id: 'local', email: 'local@buildquant.dz', user_metadata: { prenom: 'Utilisateur' } };
  accessToken = null;
  onLogin();
}

function onLogin() {
  hideAuthOverlay();
  updateSidebar();
  loadCloudProjects();
  notify('✓ Connecté — bienvenue sur BuildQuant v4 !');
}

function updateSidebar() {
  if (!currentUser) return;
  var meta     = currentUser.user_metadata || {};
  var name     = meta.prenom || currentUser.email.split('@')[0];
  var initials = name.substring(0, 2).toUpperCase();
  document.getElementById('sb-avatar').textContent = initials;
  document.getElementById('sb-name').textContent   = name;
  document.getElementById('sb-email').textContent  = currentUser.email;
}

/* ════════════════════════════════════════════
   CLOUD SAVE / LOAD — corrigé
════════════════════════════════════════════ */
async function loadCloudProjects() {
  /* Mode local : on lit le localStorage */
  if (!isCloudMode()) {
    projects = JSON.parse(localStorage.getItem('bq_v3') || '[]');
    document.getElementById('nb-projects').textContent = projects.length;
    renderDash();
    return;
  }
  /* Mode cloud : on vide le localStorage et on charge depuis Workers/D1 */
  localStorage.removeItem('bq_v3');
  projects = [];
  try {
    var rows = await supaGetProjects();
    if (rows && Array.isArray(rows)) {
      projects = rows;   // Workers renvoie déjà le JSON désérialisé
    }
  } catch(e) {
    console.error('loadCloudProjects error:', e);
  }
  document.getElementById('nb-projects').textContent = projects.length;
  renderDash();
}

async function checkSession() {
  var s = loadSession();
  if (s && s.user && s.token) {
    currentUser = s.user;
    accessToken = s.token;
    console.log('Session restored, token:', accessToken ? 'OK' : 'NULL');
    onLogin();
  } else {
    showAuthOverlay();
  }
}

/* stubs conservés pour compatibilité */
function initSupabase()      { return true; }
function waitForSupabase(cb) { cb(); }

function switchAuthTab(tab) {
  document.getElementById('auth-login-panel').style.display = tab === 'login'    ? 'block' : 'none';
  document.getElementById('auth-reg-panel').style.display   = tab === 'register' ? 'block' : 'none';
  document.querySelectorAll('.auth-tab').forEach(function(b) {
    b.style.background = b.dataset.tab === tab ? 'var(--accent)' : 'var(--surface2)';
    b.style.color      = b.dataset.tab === tab ? '#0d0f14'       : 'var(--text2)';
  });
}

/* ════════════════════════════════════════════
   BCR DATABASE — 230 articles, 5 corps d'état
   Source: BCR MHUV Algérie 2024
   Zones: nord / hauts / sud
════════════════════════════════════════════ */
var BCR = [
  /* ── VRD : Terrassement ── */
  {id:'T01',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Déblai en terrain ordinaire (TO) — pelle mécanique",u:'m³',n:650,h:580,s:520,note:'Terrain meuble'},
  {id:'T02',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Déblai en terrain semi-rocheux (TSR)",u:'m³',n:1200,h:1100,s:980,note:'Rippers nécessaires'},
  {id:'T03',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Déblai en terrain rocheux — à l'explosif",u:'m³',n:2200,h:2000,s:1800,note:'Minage inclus'},
  {id:'T04',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Déblai à la main en terrain ordinaire",u:'m³',n:950,h:880,s:820,note:'Zones inaccessibles'},
  {id:'T05',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Remblai matériaux d'apport compacté (CBR≥30)",u:'m³',n:900,h:820,s:760,note:'Compactage 95% OPM'},
  {id:'T06',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Remblai matériaux en place compacté",u:'m³',n:450,h:400,s:360,note:'Matériaux criblés sur place'},
  {id:'T07',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Décapage terre végétale (ep. moy. 20 cm)",u:'m²',n:180,h:165,s:150,note:'Mise en dépôt'},
  {id:'T08',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Réglage et nivellement terrain naturel ±3cm",u:'m²',n:120,h:110,s:100,note:'Après décapage'},
  {id:'T09',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Transport déblais en décharge ≤5 km",u:'m³',n:420,h:380,s:340,note:'Camion 12T'},
  {id:'T10',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Transport déblais en décharge 5–15 km",u:'m³',n:580,h:520,s:480,note:''},
  {id:'T11',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Transport déblais en décharge >15 km",u:'m³',n:780,h:700,s:640,note:''},
  {id:'T12',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Fouille tranchée larg. 0–0.80m, prof. 0–2m",u:'m³',n:950,h:880,s:820,note:'Blindage si nécessaire'},
  {id:'T13',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Fouille tranchée larg. 0–0.80m, prof. 2–4m",u:'m³',n:1250,h:1150,s:1050,note:'Blindage obligatoire'},
  {id:'T14',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Fouille en puits prof. ≤3m",u:'m³',n:1600,h:1450,s:1300,note:'Section ≤2×2m'},
  {id:'T15',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Remblai tranchée compacté couches 20cm",u:'m³',n:680,h:620,s:560,note:'Après pose canalisation'},
  {id:'T16',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Scarification et recompactage chaussée existante",u:'m²',n:220,h:200,s:180,note:'ep. 15cm'},
  {id:'T17',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Débroussaillage + essouchage terrain boisé",u:'m²',n:85,h:75,s:65,note:'Arbres Ø<30cm'},
  {id:'T18',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Abattage arbres Ø 30–60cm + dessouchage",u:'U',n:4500,h:4000,s:3500,note:'Évacuation bois incluse'},
  {id:'T19',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Géotextile de séparation 200g/m²",u:'m²',n:280,h:260,s:240,note:'Recouvrement 30cm'},
  {id:'T20',corps:'VRD',corpsLabel:'VRD',chap:'Terrassement',nom:"Géotextile drainant 300g/m²",u:'m²',n:380,h:350,s:320,note:'Zones humides / talus'},
  /* ── VRD : Assainissement ── */
  {id:'A01',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation béton non armé Ø200 cl.135A",u:'ml',n:2200,h:2000,s:1800,note:'Joint caoutchouc'},
  {id:'A02',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation béton non armé Ø300 cl.135A",u:'ml',n:3200,h:2900,s:2600,note:''},
  {id:'A03',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation béton non armé Ø400 cl.135A",u:'ml',n:4800,h:4400,s:4000,note:''},
  {id:'A04',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation béton armé Ø500 cl.135A (EP)",u:'ml',n:7200,h:6600,s:6000,note:'Eaux pluviales'},
  {id:'A05',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation béton armé Ø600 cl.135A",u:'ml',n:9500,h:8700,s:8000,note:''},
  {id:'A06',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation béton armé Ø800 cl.135A",u:'ml',n:14000,h:12800,s:11500,note:''},
  {id:'A07',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation PVC assainissement Ø160 SN8",u:'ml',n:1600,h:1450,s:1300,note:'Branchements EU'},
  {id:'A08',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation PVC assainissement Ø200 SN8",u:'ml',n:2100,h:1900,s:1700,note:''},
  {id:'A09',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation PVC assainissement Ø250 SN8",u:'ml',n:2900,h:2600,s:2400,note:''},
  {id:'A10',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Canalisation PVC Ø315 SN8",u:'ml',n:4200,h:3800,s:3500,note:''},
  {id:'A11',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Regard béton armé 60×60 préfabriqué + tampon fonte",u:'U',n:18500,h:16800,s:15000,note:'Tampon Ø600 T400'},
  {id:'A12',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Regard de chute béton armé coulé h≤2m",u:'U',n:32000,h:29000,s:26000,note:'Section 1×1m int.'},
  {id:'A13',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Regard de chute béton armé h 2–4m",u:'U',n:48000,h:44000,s:40000,note:''},
  {id:'A14',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Chambre de visite béton armé 1×1m h≤3m",u:'U',n:55000,h:50000,s:45000,note:'Échelon + tampon T400'},
  {id:'A15',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Grille avaloir 50×30 avec cadre fonte A15",u:'U',n:12000,h:11000,s:10000,note:'Trottoir'},
  {id:'A16',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Grille avaloir 50×50 avec cadre fonte C250",u:'U',n:16500,h:15000,s:13500,note:'Chaussée'},
  {id:'A17',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Caniveau béton préfabriqué 30×30 avec grille",u:'ml',n:2800,h:2500,s:2300,note:'Pose + joint mortier'},
  {id:'A18',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Séparateur à graisse béton armé 500L",u:'U',n:45000,h:41000,s:37000,note:''},
  {id:'A19',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Déversoir d'orage béton armé (ouvrage type)",u:'U',n:120000,h:110000,s:100000,note:'Selon débit'},
  {id:'A20',corps:'VRD',corpsLabel:'VRD',chap:'Assainissement',nom:"Essai d'étanchéité canalisation (test eau)",u:'ml',n:180,h:165,s:150,note:'Norme EN 1610'},
  /* ── VRD : AEP ── */
  {id:'P01',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite PEHD Ø63 PN16 (PE100)",u:'ml',n:1800,h:1640,s:1480,note:''},
  {id:'P02',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite PEHD Ø90 PN16",u:'ml',n:2400,h:2200,s:2000,note:''},
  {id:'P03',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite PEHD Ø110 PN16",u:'ml',n:3200,h:2900,s:2600,note:'Réseau principal'},
  {id:'P04',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite PEHD Ø125 PN16",u:'ml',n:3900,h:3550,s:3200,note:''},
  {id:'P05',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite PEHD Ø160 PN16",u:'ml',n:5500,h:5000,s:4500,note:''},
  {id:'P06',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite fonte ductile Ø100 C40",u:'ml',n:4800,h:4400,s:4000,note:'Joint automatique'},
  {id:'P07',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite fonte ductile Ø150 C40",u:'ml',n:6800,h:6200,s:5600,note:''},
  {id:'P08',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite fonte ductile Ø200 C40",u:'ml',n:9500,h:8700,s:7900,note:''},
  {id:'P09',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Conduite fonte ductile Ø300 C40",u:'ml',n:15000,h:13700,s:12400,note:''},
  {id:'P10',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Vanne sectionnement Ø80 PN16 — opercule",u:'U',n:28000,h:25500,s:23000,note:'En regard béton'},
  {id:'P11',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Vanne sectionnement Ø100 PN16",u:'U',n:35000,h:32000,s:29000,note:''},
  {id:'P12',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Vanne sectionnement Ø150 PN16",u:'U',n:55000,h:50000,s:45000,note:''},
  {id:'P13',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Bouche à clé Ø80 avec tampon fonte",u:'U',n:22000,h:20000,s:18000,note:'Regard béton inclus'},
  {id:'P14',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Borne fontaine double robinet + dallette béton",u:'U',n:75000,h:68000,s:62000,note:'AEP rurale'},
  {id:'P15',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Poteau incendie DN80 — 2 sorties",u:'U',n:95000,h:86000,s:78000,note:'NF EN 14384'},
  {id:'P16',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Regard de comptage béton armé 80×80",u:'U',n:28000,h:25500,s:23000,note:'Cadre + couvercle'},
  {id:'P17',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Ventouse automatique triple effet Ø2\"",u:'U',n:8500,h:7700,s:7000,note:'Points hauts réseau'},
  {id:'P18',corps:'VRD',corpsLabel:'VRD',chap:'AEP',nom:"Vidange / purge automatique Ø2\"",u:'U',n:6500,h:5900,s:5300,note:'Points bas réseau'},
  /* ── VRD : Enrobé/Voirie ── */
  {id:'V01',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"GNT 0/31.5 — couche de fondation (ep. 20cm compacté)",u:'m²',n:480,h:440,s:400,note:'OPM ≥ 95%'},
  {id:'V02',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"GNT 0/20 — couche de base (ep. 15cm compacté)",u:'m²',n:520,h:475,s:430,note:''},
  {id:'V03',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Grave traitée ciment GTC 0/20 (ep. 15cm)",u:'m²',n:780,h:710,s:650,note:'Rc28j ≥ 5MPa'},
  {id:'V04',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Enduit d'imprégnation bitumineux 0/1 (1,2 kg/m²)",u:'m²',n:320,h:290,s:265,note:'Cut-back CRS1'},
  {id:'V05',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Enduit de collage BCR (0,5 kg/m²)",u:'m²',n:180,h:165,s:150,note:'Avant enrobé'},
  {id:'V06',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"BBD (béton bitumineux dense) ep. 5cm",u:'m²',n:1850,h:1680,s:1520,note:'T°C ≥ 140°C'},
  {id:'V07',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"BBD ep. 6cm",u:'m²',n:2200,h:2000,s:1820,note:''},
  {id:'V08',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"BBD ep. 8cm",u:'m²',n:2900,h:2640,s:2400,note:''},
  {id:'V09',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Grave-bitume GB2 ep. 8cm",u:'m²',n:2800,h:2550,s:2320,note:'Couche de liaison'},
  {id:'V10',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Grave-bitume GB3 ep. 10cm",u:'m²',n:3400,h:3100,s:2820,note:''},
  {id:'V11',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Béton de ciment (BC) ep. 20cm — route forte trafic",u:'m²',n:5200,h:4750,s:4300,note:'Rc28j ≥ 30MPa'},
  {id:'V12',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Fraisage enrobé existant ep. 5cm",u:'m²',n:380,h:345,s:310,note:''},
  {id:'V13',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Bordure T2 béton préfabriqué 100×20×8cm",u:'ml',n:1200,h:1090,s:990,note:'Pose sur béton maigre'},
  {id:'V14',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Bordure T3 béton préfabriqué 100×25×15cm",u:'ml',n:1650,h:1500,s:1360,note:''},
  {id:'V15',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Dallage trottoir béton vibré ep. 10cm sur GNT",u:'m²',n:1800,h:1640,s:1490,note:'350 kg/m³'},
  {id:'V16',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Pavé autobloquant 6cm (80×120mm) sur sable",u:'m²',n:2200,h:2000,s:1820,note:''},
  {id:'V17',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Marquage routier peinture thermoplastique (axe)",u:'ml',n:280,h:255,s:230,note:'Largeur 15cm'},
  {id:'V18',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Signalisation verticale panneau A (triangle)",u:'U',n:4500,h:4100,s:3700,note:'Mât galvanisé inclus'},
  {id:'V19',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Glissière sécurité GBA béton (New Jersey)",u:'ml',n:12000,h:10900,s:9900,note:'Préfabriqué'},
  {id:'V20',corps:'VRD',corpsLabel:'VRD',chap:'Voirie / Enrobé',nom:"Éclairage public mât 8m + luminaire LED 80W",u:'U',n:85000,h:77400,s:70300,note:'Câblage non inclus'},
  /* ── Gros Œuvre ── */
  {id:'F01',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Béton de propreté dosé 150 kg/m³ (ep. 10cm)",u:'m³',n:9500,h:8700,s:7900,note:'Sous semelles'},
  {id:'F02',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Fouille en pleine masse pour fondations",u:'m³',n:850,h:780,s:710,note:'TO'},
  {id:'F03',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Semelle filante béton armé — dosage 350 kg/m³",u:'m³',n:28000,h:25500,s:23000,note:'Coffrage+ferraillage'},
  {id:'F04',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Semelle isolée béton armé — dosage 350 kg/m³",u:'m³',n:32000,h:29000,s:26000,note:''},
  {id:'F05',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Radier général béton armé ep. 25cm",u:'m³',n:35000,h:32000,s:29000,note:'350 kg/m³'},
  {id:'F06',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Pieux forés Ø400 béton armé",u:'ml',n:18000,h:16400,s:14900,note:''},
  {id:'F07',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Pieux forés Ø600 béton armé",u:'ml',n:28000,h:25500,s:23200,note:''},
  {id:'F08',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Pieux forés Ø800 béton armé",u:'ml',n:42000,h:38300,s:34900,note:''},
  {id:'F09',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Fondations',nom:"Longrine de liaison béton armé",u:'m³',n:30000,h:27300,s:24900,note:'Entre semelles'},
  {id:'B01',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Voile béton armé ep. 15cm — dosage 350 kg/m³",u:'m³',n:45000,h:41000,s:37300,note:'Coffrage 2 faces'},
  {id:'B02',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Voile béton armé ep. 20cm",u:'m³',n:42000,h:38200,s:34800,note:''},
  {id:'B03',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Poteau béton armé section 30×30",u:'m³',n:55000,h:50100,s:45600,note:'Coffrage+ferraillage'},
  {id:'B04',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Poteau béton armé section 40×40",u:'m³',n:52000,h:47400,s:43200,note:''},
  {id:'B05',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Poutre principale béton armé — dosage 350",u:'m³',n:52000,h:47400,s:43200,note:''},
  {id:'B06',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Dalle pleine ep. 15cm béton armé",u:'m³',n:48000,h:43700,s:39800,note:''},
  {id:'B07',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Dalle pleine ep. 20cm béton armé",u:'m³',n:46000,h:41900,s:38200,note:''},
  {id:'B08',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Corps creux 20+5 — dalle nervurée",u:'m²',n:3200,h:2912,s:2651,note:'Avec poutrelles'},
  {id:'B09',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Corps creux 16+4 — dalle nervurée",u:'m²',n:2900,h:2641,s:2405,note:''},
  {id:'B10',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Escalier béton armé (paillasse + marches)",u:'m²',n:8500,h:7735,s:7048,note:'Coffrage complexe'},
  {id:'B11',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Béton Armé',nom:"Acier haute adhérence FeE500 — fourni+posé",u:'kg',n:200,h:182,s:166,note:''},
  {id:'M01',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Maçonnerie',nom:"Maçonnerie moellon tout venant ep. 40cm",u:'m³',n:8500,h:7735,s:7048,note:'Mortier 400 kg/m³'},
  {id:'M02',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Maçonnerie',nom:"Briques creuses 8 trous 10cm — cloison",u:'m²',n:950,h:866,s:789,note:''},
  {id:'M03',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Maçonnerie',nom:"Briques creuses 8 trous 15cm — cloison",u:'m²',n:1100,h:1001,s:912,note:''},
  {id:'M04',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Maçonnerie',nom:"Briques creuses 10 trous 20cm — mur extérieur",u:'m²',n:1350,h:1229,s:1120,note:''},
  {id:'M05',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Maçonnerie',nom:"Double cloison briques 10+10cm + lame air",u:'m²',n:2400,h:2184,s:1989,note:'Façade isolation'},
  {id:'M06',corps:'GO',corpsLabel:'Gros Œuvre',chap:'Maçonnerie',nom:"Agglos creux 20×20×40 — mur porteur",u:'m²',n:1650,h:1502,s:1368,note:''},
  /* ── Second Œuvre ── */
  {id:'E01',corps:'SO',corpsLabel:'Second Œuvre',chap:'Plâtrerie / Enduits',nom:"Enduit de plâtre intérieur — 3 couches",u:'m²',n:1200,h:1092,s:994,note:'ep. 15mm'},
  {id:'E02',corps:'SO',corpsLabel:'Second Œuvre',chap:'Plâtrerie / Enduits',nom:"Enduit ciment hydrofugé extérieur — 3 couches",u:'m²',n:1450,h:1320,s:1202,note:'ep. 20mm'},
  {id:'E03',corps:'SO',corpsLabel:'Second Œuvre',chap:'Plâtrerie / Enduits',nom:"Enduit de rebouchage et lissage",u:'m²',n:480,h:437,s:398,note:'Avant peinture'},
  {id:'E04',corps:'SO',corpsLabel:'Second Œuvre',chap:'Plâtrerie / Enduits',nom:"Faux-plafond plâtre BA13 sur ossature galva",u:'m²',n:3200,h:2912,s:2651,note:''},
  {id:'E05',corps:'SO',corpsLabel:'Second Œuvre',chap:'Plâtrerie / Enduits',nom:"Faux-plafond plâtre hydrofuge BA18H",u:'m²',n:3800,h:3458,s:3148,note:'Salles humides'},
  {id:'E06',corps:'SO',corpsLabel:'Second Œuvre',chap:'Plâtrerie / Enduits',nom:"Doublage isolant complexe 13+100 PSE",u:'m²',n:3500,h:3185,s:2901,note:''},
  {id:'R01',corps:'SO',corpsLabel:'Second Œuvre',chap:'Revêtements',nom:"Carrelage grès cérame 30×30 — pose colle",u:'m²',n:2800,h:2548,s:2320,note:''},
  {id:'R02',corps:'SO',corpsLabel:'Second Œuvre',chap:'Revêtements',nom:"Carrelage grès cérame 40×40",u:'m²',n:3200,h:2912,s:2651,note:''},
  {id:'R03',corps:'SO',corpsLabel:'Second Œuvre',chap:'Revêtements',nom:"Carrelage grès cérame 60×60",u:'m²',n:4500,h:4095,s:3730,note:''},
  {id:'R04',corps:'SO',corpsLabel:'Second Œuvre',chap:'Revêtements',nom:"Carrelage grès antidérapant R11",u:'m²',n:3500,h:3185,s:2901,note:'Escaliers'},
  {id:'R05',corps:'SO',corpsLabel:'Second Œuvre',chap:'Revêtements',nom:"Faïence murale 20×30 cm",u:'m²',n:2400,h:2184,s:1989,note:'H=2m'},
  {id:'R06',corps:'SO',corpsLabel:'Second Œuvre',chap:'Revêtements',nom:"Chape ciment lissée 350 kg/m³ — ep. 5cm",u:'m²',n:780,h:710,s:646,note:''},
  {id:'R07',corps:'SO',corpsLabel:'Second Œuvre',chap:'Revêtements',nom:"Parquet stratifié 8mm AC4 (pose flottante)",u:'m²',n:3800,h:3458,s:3148,note:'Sous-couche incluse'},
  {id:'ET1',corps:'SO',corpsLabel:'Second Œuvre',chap:'Étanchéité',nom:"Étanchéité bicouche SBS autoprotégée — toiture",u:'m²',n:2800,h:2548,s:2320,note:'2 feutres'},
  {id:'ET2',corps:'SO',corpsLabel:'Second Œuvre',chap:'Étanchéité',nom:"Étanchéité monocouche APP ardoisée",u:'m²',n:2200,h:2002,s:1822,note:''},
  {id:'ET3',corps:'SO',corpsLabel:'Second Œuvre',chap:'Étanchéité',nom:"Isolation PSE 10cm sous étanchéité",u:'m²',n:1200,h:1092,s:994,note:''},
  {id:'ET4',corps:'SO',corpsLabel:'Second Œuvre',chap:'Étanchéité',nom:"Protection béton gravillonné sur étanchéité",u:'m²',n:680,h:619,s:564,note:'Ep. 5cm'},
  {id:'ET5',corps:'SO',corpsLabel:'Second Œuvre',chap:'Étanchéité',nom:"Hydrofugation murs enterrés (coating bitumineux)",u:'m²',n:1200,h:1092,s:994,note:'3 couches'},
  {id:'PT1',corps:'SO',corpsLabel:'Second Œuvre',chap:'Peinture',nom:"Peinture vinylique intérieure — 2 couches",u:'m²',n:650,h:592,s:539,note:'Sur enduit lissé'},
  {id:'PT2',corps:'SO',corpsLabel:'Second Œuvre',chap:'Peinture',nom:"Peinture acrylique extérieure — 3 couches",u:'m²',n:950,h:865,s:788,note:'Résistance UV'},
  {id:'PT3',corps:'SO',corpsLabel:'Second Œuvre',chap:'Peinture',nom:"Peinture glycérophtalique — portes+boiseries",u:'m²',n:800,h:728,s:663,note:''},
  {id:'PT4',corps:'SO',corpsLabel:'Second Œuvre',chap:'Peinture',nom:"Peinture époxy sol (garage + sous-sol)",u:'m²',n:1800,h:1638,s:1491,note:'2 couches 200µ'},
  /* ── Électricité / Plomberie / CVC ── */
  {id:'EL1',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Tableau divisionnaire TDB 24 modules (câblé)",u:'U',n:35000,h:31900,s:29000,note:'Disjoncteurs inclus'},
  {id:'EL2',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Câble U-1000 R2V 3×2.5mm² — pose en gaine",u:'ml',n:680,h:619,s:564,note:'Circuits prise'},
  {id:'EL3',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Câble U-1000 R2V 3×1.5mm² — pose en gaine",u:'ml',n:580,h:528,s:481,note:'Circuits éclairage'},
  {id:'EL4',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Câble U-1000 R2V 5×6mm² — alimentation",u:'ml',n:1200,h:1092,s:994,note:''},
  {id:'EL5',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Interrupteur simple allumage encastré",u:'U',n:1800,h:1638,s:1491,note:'Avec boîtier'},
  {id:'EL6',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Prise de courant 16A+T encastrée",u:'U',n:2200,h:2002,s:1822,note:''},
  {id:'EL7',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Luminaire plafonnier LED 12W",u:'U',n:3500,h:3185,s:2901,note:'Installé'},
  {id:'EL8',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Réglette fluorescente étanche 36W",u:'U',n:4500,h:4095,s:3730,note:'Locaux techniques'},
  {id:'EL9',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Spot encastré LED 7W (faux-plafond)",u:'U',n:2800,h:2548,s:2320,note:''},
  {id:'EL10',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Électricité',nom:"Détecteur de fumée NF/EN54",u:'U',n:4500,h:4095,s:3730,note:''},
  {id:'PL1',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Plomberie',nom:"Tube cuivre Ø12/14 — eau chaude/froide",u:'ml',n:1200,h:1092,s:994,note:"Soudé à l'étain"},
  {id:'PL2',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Plomberie',nom:"Tube PPR Ø20 PN20 (eau chaude sanitaire)",u:'ml',n:780,h:710,s:646,note:''},
  {id:'PL3',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Plomberie',nom:"WC à réservoir céramique standard",u:'U',n:28000,h:25480,s:23197,note:'Fourni+posé'},
  {id:'PL4',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Plomberie',nom:"Lavabo céramique 60cm + robinetterie",u:'U',n:22000,h:20020,s:18218,note:''},
  {id:'PL5',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Plomberie',nom:"Baignoire acrylique 160cm + mitigeur",u:'U',n:55000,h:50050,s:45580,note:''},
  {id:'PL6',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Plomberie',nom:"Douche à l'italienne + receveur + mitigeur",u:'U',n:65000,h:59150,s:53861,note:''},
  {id:'PL7',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Plomberie',nom:"Chauffe-eau électrique 100L",u:'U',n:35000,h:31850,s:29003,note:''},
  {id:'PL8',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'Plomberie',nom:"Chauffe-eau solaire 200L (thermosiphon)",u:'U',n:180000,h:163800,s:149100,note:'Installation complète'},
  {id:'CVC1',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'CVC',nom:"Climatiseur split mural 9000 BTU (R32)",u:'U',n:85000,h:77350,s:70448,note:'Fourni+posé+gaz'},
  {id:'CVC2',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'CVC',nom:"Climatiseur split mural 12000 BTU",u:'U',n:110000,h:100100,s:91100,note:''},
  {id:'CVC3',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'CVC',nom:"Climatiseur split mural 18000 BTU",u:'U',n:145000,h:131950,s:120183,note:''},
  {id:'CVC4',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'CVC',nom:"Climatiseur cassette 24000 BTU",u:'U',n:220000,h:200200,s:182300,note:'Faux-plafond'},
  {id:'CVC5',corps:'EP',corpsLabel:'Élec / Plomb / CVC',chap:'CVC',nom:"Ventilateur extracteur salle de bain 100m³/h",u:'U',n:8500,h:7735,s:7045,note:''},
  /* ── Menuiserie ── */
  {id:'AL1',corps:'MEN',corpsLabel:'Menuiserie',chap:'Aluminium',nom:"Fenêtre aluminium 1 vantail 60×120 — double vitrage",u:'U',n:18000,h:16380,s:14912,note:'Profil 60mm'},
  {id:'AL2',corps:'MEN',corpsLabel:'Menuiserie',chap:'Aluminium',nom:"Fenêtre aluminium 2 vantaux 120×120 — double vitrage",u:'U',n:28000,h:25480,s:23197,note:''},
  {id:'AL3',corps:'MEN',corpsLabel:'Menuiserie',chap:'Aluminium',nom:"Porte-fenêtre aluminium 2 vantaux 140×220",u:'U',n:45000,h:40950,s:37287,note:''},
  {id:'AL4',corps:'MEN',corpsLabel:'Menuiserie',chap:'Aluminium',nom:"Porte d'entrée aluminium (plein+vitré) 90×210",u:'U',n:65000,h:59150,s:53871,note:''},
  {id:'AL5',corps:'MEN',corpsLabel:'Menuiserie',chap:'Aluminium',nom:"Garde-corps aluminium H=1m — balcon",u:'ml',n:18000,h:16380,s:14912,note:''},
  {id:'AL6',corps:'MEN',corpsLabel:'Menuiserie',chap:'Aluminium',nom:"Rideau métallique aluminium 3m (commerce)",u:'U',n:120000,h:109200,s:99400,note:''},
  {id:'BO1',corps:'MEN',corpsLabel:'Menuiserie',chap:'Menuiserie Bois',nom:"Porte isoplane bois 83×205cm — intérieure",u:'U',n:12000,h:10920,s:9942,note:'Quincaillerie incluse'},
  {id:'BO2',corps:'MEN',corpsLabel:'Menuiserie',chap:'Menuiserie Bois',nom:"Porte pleine bois massif 90×210cm",u:'U',n:28000,h:25480,s:23197,note:'Chêne ou sapelli'},
  {id:'BO3',corps:'MEN',corpsLabel:'Menuiserie',chap:'Menuiserie Bois',nom:"Bloc-porte bois complet (cadre+paumelles+serrure)",u:'U',n:15000,h:13650,s:12432,note:'Prépeint'},
  {id:'PV1',corps:'MEN',corpsLabel:'Menuiserie',chap:'PVC',nom:"Fenêtre PVC 2 vantaux 120×120 — double vitrage",u:'U',n:22000,h:20020,s:18218,note:'5 chambres'},
  {id:'PV2',corps:'MEN',corpsLabel:'Menuiserie',chap:'PVC',nom:"Porte-fenêtre PVC 2 vantaux 140×220",u:'U',n:35000,h:31850,s:29003,note:''},
  {id:'PV3',corps:'MEN',corpsLabel:'Menuiserie',chap:'PVC',nom:"Volet roulant PVC motorisé 120×120",u:'U',n:28000,h:25480,s:23197,note:'Caisson incorporé'},
  {id:'MT1',corps:'MEN',corpsLabel:'Menuiserie',chap:'Métallerie',nom:"Porte métallique simple 90×210cm — galvanisé",u:'U',n:25000,h:22750,s:20720,note:'Quincaillerie incluse'},
  {id:'MT2',corps:'MEN',corpsLabel:'Menuiserie',chap:'Métallerie',nom:"Portail coulissant motorisé L=5m",u:'U',n:220000,h:200200,s:182300,note:'Moteur 220V'},
  {id:'MT3',corps:'MEN',corpsLabel:'Menuiserie',chap:'Métallerie',nom:"Portail battant 2 vantaux L=4m",u:'U',n:120000,h:109200,s:99400,note:'Acier galvanisé'},
  {id:'MT4',corps:'MEN',corpsLabel:'Menuiserie',chap:'Métallerie',nom:"Garde-corps acier galvanisé H=1m",u:'ml',n:12000,h:10920,s:9942,note:''},
  {id:'MT5',corps:'MEN',corpsLabel:'Menuiserie',chap:'Métallerie',nom:"Grille de défense fenêtre en fer forgé",u:'m²',n:8500,h:7735,s:7045,note:''},
  {id:'MT6',corps:'MEN',corpsLabel:'Menuiserie',chap:'Métallerie',nom:"Main courante acier inox Ø42",u:'ml',n:15000,h:13650,s:12432,note:'Fixation murale'},
];

document.getElementById('nb-bcr').textContent = BCR.length;

/* Corps meta */
var CORPS_META = {
  VRD: { label: 'VRD',          cls: 'corps-vrd' },
  GO:  { label: 'Gros Œuvre',   cls: 'corps-go'  },
  SO:  { label: 'Second Œuvre', cls: 'corps-so'  },
  EP:  { label: 'Élec/Plomb',   cls: 'corps-ep'  },
  MEN: { label: 'Menuiserie',   cls: 'corps-men' },
};

/* ════════════════════════════════════════════
   STATE
════════════════════════════════════════════ */
var projects      = [];
var chapCounter   = 0;
var rowCounters   = {};
var selectedChap  = null;
var activeZone    = 'nord';
var activeZonePage= 'nord';
var bcrFilter     = 'all';
var bcrPageFilter = 'all';

/* ════════════════════════════════════════════
   NAVIGATION
════════════════════════════════════════════ */
var PT = {
  dashboard:     ['Tableau de bord',    "Vue d'ensemble de vos projets"],
  projects:      ['Mes Projets DQE',    'Tous vos projets structurés par chapitres'],
  'new-project': ['Nouveau Projet DQE', 'BCR intégrée — insérez les articles instantanément'],
  bcr:           ['Recherche BCR',      "Base de Coûts de Référence — 5 corps d'état · 3 zones"],
  'bcr-browse':  ['Catalogue BCR',      'Tous les articles classés par corps d\'état'],
};
var BN_MAP = {
  'dashboard':   'bn-dash',
  'projects':    'bn-projects',
  'new-project': 'bn-new',
  'bcr':         'bn-bcr',
  'bcr-browse':  'bn-catalogue',
};

function nav(page, el) {
  document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
  document.getElementById('page-' + page).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(function(n) { n.classList.remove('active'); });
  if (el) el.classList.add('active');
  if (PT[page]) {
    document.getElementById('page-title').textContent = PT[page][0];
    document.getElementById('page-sub').textContent   = PT[page][1];
  }
  setBN(BN_MAP[page] || 'bn-dash');
  window.scrollTo(0, 0);
  if (page === 'dashboard')   renderDash();
  if (page === 'projects')    renderProjects();
  if (page === 'new-project') { resetForm(); initBCRPanel(); }
  if (page === 'bcr')         initBCRPage();
  if (page === 'bcr-browse')  initBCRBrowse();
}

/* ════════════════════════════════════════════
   ZONE
════════════════════════════════════════════ */
function setZone(z) {
  activeZone = z;
  ['nord','hauts','sud'].forEach(function(x) {
    var b = document.getElementById('zb-' + x);
    if (b) b.className = 'zone-btn' + (x === z ? ' active-' + x : '');
  });
  renderBCRPanel();
}
function setZonePage(z) {
  activeZonePage = z;
  ['nord','hauts','sud'].forEach(function(x) {
    var b = document.getElementById('pzb-' + x);
    if (b) b.className = 'zone-btn' + (x === z ? ' active-' + x : '');
  });
  renderBCRPage();
}
function priceFor(item, zone) {
  return zone === 'hauts' ? item.h : zone === 'sud' ? item.s : item.n;
}

/* ════════════════════════════════════════════
   BCR SEARCH — Helpers
════════════════════════════════════════════ */
function highlight(text, q) {
  if (!q) return text;
  var re = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
  return text.replace(re, '<mark>$1</mark>');
}

function buildFilters(containerId, active, setter, renderFn) {
  var corps  = ['all','VRD','GO','SO','EP','MEN'];
  var labels = { all:'Tous', VRD:'VRD', GO:'Gros Œuvre', SO:'Second Œuvre', EP:'Élec/Plomb', MEN:'Menuiserie' };
  var c = document.getElementById(containerId);
  if (!c) return;
  c.innerHTML = '';
  corps.forEach(function(k) {
    var b = document.createElement('button');
    b.className = 'bcr-filter-btn' + (active === k ? ' active' : '');
    b.textContent = labels[k];
    b.onclick = function() { setter(k); renderFn(); };
    c.appendChild(b);
  });
}

function renderBCRItems(containerId, query, zone, filter, addable) {
  var c = document.getElementById(containerId);
  if (!c) return;
  var q = (query || '').toLowerCase().trim();
  var filtered = BCR.filter(function(item) {
    var matchCorp = filter === 'all' || item.corps === filter;
    var matchQ = !q
      || item.nom.toLowerCase().indexOf(q) >= 0
      || item.id.toLowerCase().indexOf(q) >= 0
      || item.chap.toLowerCase().indexOf(q) >= 0
      || item.corpsLabel.toLowerCase().indexOf(q) >= 0
      || item.u.toLowerCase().indexOf(q) >= 0;
    return matchCorp && matchQ;
  });

  var countEl = document.getElementById(containerId === 'bcr-panel-results' ? 'bcr-panel-count' : 'bcr-page-count');
  if (countEl) countEl.textContent = filtered.length + ' / ' + BCR.length;

  if (!filtered.length) {
    c.innerHTML = '<div class="bcr-empty"><div class="bcr-empty-icon">🔍</div><p>Aucun article trouvé</p></div>';
    return;
  }
  c.innerHTML = '';
  filtered.forEach(function(item) {
    var price = priceFor(item, zone);
    var meta  = CORPS_META[item.corps] || { cls:'', label:'' };
    var div   = document.createElement('div');
    div.className = 'bcr-item';
    div.innerHTML =
      '<div class="bcr-item-left">' +
        '<div class="bcr-item-code">' + item.id + ' · ' + item.chap + '</div>' +
        '<div class="bcr-item-name">' + highlight(item.nom, q) + '</div>' +
        '<div class="bcr-item-meta">' +
          '<span class="bcr-item-corps ' + meta.cls + '">' + meta.label + '</span>' +
          (item.note ? '<span class="bcr-item-chap">' + item.note + '</span>' : '') +
        '</div>' +
      '</div>' +
      '<div class="bcr-item-right">' +
        '<div class="bcr-item-price">' + fmtN(price) + ' DA</div>' +
        '<div class="bcr-item-unit">/ ' + item.u + '</div>' +
      '</div>' +
      (addable ? '<div class="bcr-item-add" title="Ajouter au chapitre actif">+</div>' : '');
    if (addable) {
      div.querySelector('.bcr-item-add').onclick = function(e) { e.stopPropagation(); insertBCRItem(item, zone); };
      div.onclick = function() { insertBCRItem(item, zone); };
    }
    c.appendChild(div);
  });
}

/* ════════════════════════════════════════════
   BCR PANEL (inside new-project)
════════════════════════════════════════════ */
function initBCRPanel() {
  bcrFilter = 'all';
  buildFilters('bcr-panel-filters', bcrFilter, function(v) { bcrFilter = v; }, renderBCRPanel);
  renderBCRPanel();
}
function renderBCRPanel() {
  buildFilters('bcr-panel-filters', bcrFilter, function(v) { bcrFilter = v; renderBCRPanel(); }, renderBCRPanel);
  var q = document.getElementById('bcr-panel-search');
  renderBCRItems('bcr-panel-results', q ? q.value : '', activeZone, bcrFilter, true);
}
function insertBCRItem(item, zone) {
  if (!selectedChap) { notify('⚠ Sélectionnez un chapitre d\'abord'); return; }
  var price = priceFor(item, zone || activeZone);
  addRow(selectedChap, item.nom, item.u, price, 1);
  notify('✓ "' + item.id + '" ajouté · ' + fmtN(price) + ' DA/' + item.u);
}

/* ════════════════════════════════════════════
   BCR PAGE
════════════════════════════════════════════ */
function initBCRPage() {
  bcrPageFilter = 'all';
  buildFilters('bcr-page-filters', bcrPageFilter, function(v) { bcrPageFilter = v; renderBCRPage(); }, renderBCRPage);
  renderBCRPage();
}
function renderBCRPage() {
  buildFilters('bcr-page-filters', bcrPageFilter, function(v) { bcrPageFilter = v; renderBCRPage(); }, renderBCRPage);
  var q = document.getElementById('bcr-page-search');
  var c = document.getElementById('bcr-page-results');
  if (!c) return;
  c.style.display              = 'grid';
  c.style.gridTemplateColumns  = 'repeat(auto-fill,minmax(300px,1fr))';
  c.style.gap                  = '8px';
  renderBCRItems('bcr-page-results', q ? q.value : '', activeZonePage, bcrPageFilter, false);
}

/* ════════════════════════════════════════════
   BCR BROWSE (catalogue)
════════════════════════════════════════════ */
var browseCorp = 'VRD';
function initBCRBrowse() {
  var tabsEl = document.getElementById('bcr-browse-tabs');
  var corps  = Object.keys(CORPS_META);
  tabsEl.innerHTML = '';
  corps.forEach(function(k) {
    var b = document.createElement('button');
    b.className = 'tab' + (k === browseCorp ? ' active' : '');
    b.textContent = CORPS_META[k].label;
    b.onclick = function() {
      browseCorp = k;
      tabsEl.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
      b.classList.add('active');
      renderBrowse();
    };
    tabsEl.appendChild(b);
  });
  renderBrowse();
}
function renderBrowse() {
  var c     = document.getElementById('bcr-browse-content');
  var items = BCR.filter(function(i) { return i.corps === browseCorp; });
  var chaps = {};
  items.forEach(function(i) { if (!chaps[i.chap]) chaps[i.chap] = []; chaps[i.chap].push(i); });
  var html = '';
  Object.keys(chaps).forEach(function(ch) {
    html += '<div style="margin-bottom:20px;"><div style="background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;">' +
      '<div style="padding:10px 16px;background:var(--surface2);border-bottom:1px solid var(--border);font-family:\'Syne\',sans-serif;font-size:12px;font-weight:700;color:var(--accent);">' + ch + ' <span style="color:var(--text3);font-weight:400;font-size:11px;">(' + chaps[ch].length + ' articles)</span></div>' +
      '<table style="width:100%;border-collapse:collapse;font-size:12px;"><thead><tr>' +
      '<th style="padding:8px 14px;text-align:left;font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid var(--border);background:var(--surface2);">Code</th>' +
      '<th style="padding:8px 14px;text-align:left;font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid var(--border);background:var(--surface2);">Désignation</th>' +
      '<th style="padding:8px 14px;text-align:center;font-size:10px;color:var(--text3);text-transform:uppercase;border-bottom:1px solid var(--border);background:var(--surface2);">Unité</th>' +
      '<th style="padding:8px 14px;text-align:right;font-size:10px;color:#90CAF9;text-transform:uppercase;border-bottom:1px solid var(--border);background:rgba(21,101,192,.08);">Nord</th>' +
      '<th style="padding:8px 14px;text-align:right;font-size:10px;color:#CE93D8;text-transform:uppercase;border-bottom:1px solid var(--border);background:rgba(106,27,154,.08);">Hauts-P.</th>' +
      '<th style="padding:8px 14px;text-align:right;font-size:10px;color:#FFCC80;text-transform:uppercase;border-bottom:1px solid var(--border);background:rgba(230,81,0,.08);">Sud</th>' +
      '</tr></thead><tbody>';
    chaps[ch].forEach(function(item) {
      html += '<tr style="border-bottom:1px solid var(--border);">' +
        '<td style="padding:8px 14px;color:var(--text3);font-size:10.5px;font-weight:600;">' + item.id + '</td>' +
        '<td style="padding:8px 14px;color:var(--text);font-size:12px;">' + item.nom + (item.note ? '<br/><span style="font-size:10px;color:var(--text3);">' + item.note + '</span>' : '') + '</td>' +
        '<td style="padding:8px 14px;text-align:center;color:var(--text2);font-size:11.5px;font-weight:600;">' + item.u + '</td>' +
        '<td style="padding:8px 14px;text-align:right;color:#90CAF9;font-weight:600;font-size:12px;background:rgba(21,101,192,.04);">' + fmtN(item.n) + ' DA</td>' +
        '<td style="padding:8px 14px;text-align:right;color:#CE93D8;font-weight:600;font-size:12px;background:rgba(106,27,154,.04);">' + fmtN(item.h) + ' DA</td>' +
        '<td style="padding:8px 14px;text-align:right;color:#FFCC80;font-weight:600;font-size:12px;background:rgba(230,81,0,.04);">' + fmtN(item.s) + ' DA</td>' +
        '</tr>';
    });
    html += '</tbody></table></div></div>';
  });
  c.innerHTML = html;
}

/* ════════════════════════════════════════════
   DQE CHAPITRES ENGINE
════════════════════════════════════════════ */
function addChap(name) {
  chapCounter++;
  var cid = 'c' + chapCounter;
  rowCounters[cid] = 0;
  var div = document.createElement('div');
  div.className = 'chap-block';
  div.id = cid;
  div.innerHTML =
    '<div class="chap-header" onclick="toggleChap(\'' + cid + '\')" id="hdr-' + cid + '">' +
      '<div class="chap-num">' + chapCounter + '</div>' +
      '<input class="chap-name-input" type="text" placeholder="Nom du chapitre..." value="' + (name || '') + '" onclick="event.stopPropagation();selectChap(\'' + cid + '\')" oninput="event.stopPropagation()"/>' +
      '<span class="chap-st" id="st-' + cid + '">0 DA</span>' +
      '<span onclick="event.stopPropagation();deleteChap(\'' + cid + '\')"><button class="del-btn" style="font-size:12px;margin:0 2px;">✕</button></span>' +
      '<span class="chap-toggle open" id="tgl-' + cid + '">▶</span>' +
    '</div>' +
    '<div class="chap-body" id="bd-' + cid + '">' +
      '<div class="bpu-wrap"><table class="bpu-tbl">' +
        '<thead><tr><th style="width:32px;">N°</th><th>Désignation</th><th style="width:52px;">Unité</th><th style="width:75px;">Quantité</th><th style="width:95px;">P.U. (DA)</th><th style="width:105px;">Montant HT</th><th style="width:28px;"></th></tr></thead>' +
        '<tbody id="tb-' + cid + '"></tbody>' +
        '<tfoot><tr class="st-row"><td colspan="5" style="text-align:right;font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;">Sous-total Chap. ' + chapCounter + ' :</td><td id="stf-' + cid + '">0 DA</td><td></td></tr></tfoot>' +
      '</table></div>' +
      '<div class="chap-add-row"><button class="btn btn-ghost btn-sm" onclick="addRow(\'' + cid + '\')">+ Ligne manuelle</button></div>' +
    '</div>';
  document.getElementById('chaps-container').appendChild(div);
  selectChap(cid);
  recalcAll();
}

function selectChap(cid) {
  selectedChap = cid;
  document.querySelectorAll('.chap-block').forEach(function(b) { b.classList.remove('selected'); });
  var el = document.getElementById(cid);
  if (el) el.classList.add('selected');
  var name = el ? el.querySelector('.chap-name-input').value || ('Chapitre ' + cid.replace('c', '')) : '';
  var info = document.getElementById('bcr-target-info');
  if (info) info.textContent = '→ Chapitre actif : ' + name;
}

function toggleChap(cid) {
  var bd  = document.getElementById('bd-' + cid);
  var tgl = document.getElementById('tgl-' + cid);
  if (!bd) return;
  bd.classList.toggle('collapsed');
  if (tgl) tgl.classList.toggle('open');
}
function deleteChap(cid) {
  if (confirm('Supprimer ce chapitre ?')) {
    var el = document.getElementById(cid);
    if (el) el.remove();
    if (selectedChap === cid) {
      selectedChap = null;
      var info = document.getElementById('bcr-target-info');
      if (info) info.textContent = 'Sélectionnez un chapitre';
    }
    recalcAll();
  }
}
function collapseAll() { document.querySelectorAll('.chap-body').forEach(function(b) { b.classList.add('collapsed'); }); document.querySelectorAll('.chap-toggle').forEach(function(t) { t.classList.remove('open'); }); }
function expandAll()   { document.querySelectorAll('.chap-body').forEach(function(b) { b.classList.remove('collapsed'); }); document.querySelectorAll('.chap-toggle').forEach(function(t) { t.classList.add('open'); }); }

/* ── Rows ── */
function addRow(cid, desig, unite, prix, qty) {
  if (!rowCounters[cid]) rowCounters[cid] = 0;
  rowCounters[cid]++;
  var rid = cid + '-r' + rowCounters[cid];
  var tb  = document.getElementById('tb-' + cid);
  if (!tb) return;
  var tr = document.createElement('tr');
  tr.id = rid;
  tr.innerHTML =
    '<td style="text-align:center;color:var(--text3);font-size:10.5px;">' + rowCounters[cid] + '</td>' +
    '<td><input type="text" placeholder="Désignation..." value="' + (desig || '') + '" oninput="calcChap(\'' + cid + '\')" style="min-width:140px;width:100%;"/></td>' +
    '<td><select onchange="calcChap(\'' + cid + '\')">' + 'ml,m²,m³,U,kg,t,Fft'.split(',').map(function(x) { return '<option' + (x === (unite || 'ml') ? ' selected' : '') + '>' + x + '</option>'; }).join('') + '</select></td>' +
    '<td><input type="number" min="0" step="0.01" value="' + (qty || 1) + '" oninput="calcChap(\'' + cid + '\')" style="width:65px;"/></td>' +
    '<td><input type="number" min="0" step="1" value="' + (prix || 0) + '" oninput="calcChap(\'' + cid + '\')" style="width:85px;"/></td>' +
    '<td class="montant-c" id="m-' + rid + '">' + fmtN((qty || 1) * (prix || 0)) + ' DA</td>' +
    '<td><button class="del-btn" onclick="delRow(\'' + rid + '\',\'' + cid + '\')">×</button></td>';
  tb.appendChild(tr);
  calcChap(cid);
}
function delRow(rid, cid) { var el = document.getElementById(rid); if (el) el.remove(); calcChap(cid); }

function calcChap(cid) {
  var tb = document.getElementById('tb-' + cid);
  if (!tb) return;
  var total = 0;
  tb.querySelectorAll('tr').forEach(function(tr) {
    var ni = tr.querySelectorAll('input[type="number"]');
    if (ni.length >= 2) {
      var m = (parseFloat(ni[0].value) || 0) * (parseFloat(ni[1].value) || 0);
      total += m;
      var cell = document.getElementById('m-' + tr.id);
      if (cell) cell.textContent = fmtN(m) + ' DA';
    }
  });
  var st  = document.getElementById('st-'  + cid);
  var stf = document.getElementById('stf-' + cid);
  if (st)  st.textContent  = fmtN(total) + ' DA';
  if (stf) stf.textContent = fmtN(total) + ' DA';
  recalcAll();
}

function recalcAll() {
  var grandHT = 0, recapHTML = '';
  document.querySelectorAll('.chap-block').forEach(function(b) {
    var cid  = b.id;
    var num  = b.querySelector('.chap-num').textContent;
    var name = b.querySelector('.chap-name-input').value || ('Chapitre ' + num);
    var sub  = 0;
    var tb   = document.getElementById('tb-' + cid);
    if (tb) tb.querySelectorAll('tr').forEach(function(tr) {
      var ni = tr.querySelectorAll('input[type="number"]');
      if (ni.length >= 2) sub += (parseFloat(ni[0].value) || 0) * (parseFloat(ni[1].value) || 0);
    });
    grandHT += sub;
    recapHTML += '<div style="display:flex;justify-content:space-between;padding:5px 0;font-size:12px;border-bottom:1px solid var(--border);"><span style="color:var(--text3);">Chap.' + num + ' — ' + name + '</span><span style="font-weight:600;">' + fmtN(sub) + ' DA</span></div>';
  });
  document.getElementById('chaps-recap').innerHTML = recapHTML;
  var tva  = parseInt(document.getElementById('p-tva').value) || 0;
  var tvaV = grandHT * tva / 100;
  document.getElementById('t-ht').textContent      = fmtN(grandHT) + ' DA';
  document.getElementById('t-tva-lbl').textContent = 'TVA (' + tva + '%)';
  document.getElementById('t-tva').textContent     = fmtN(tvaV) + ' DA';
  document.getElementById('t-ttc').textContent     = fmtN(grandHT + tvaV) + ' DA';
}

/* ════════════════════════════════════════════
   SAVE / COLLECT
════════════════════════════════════════════ */
function collectData() {
  var chaps = [], grandHT = 0;
  document.querySelectorAll('.chap-block').forEach(function(b) {
    var cid  = b.id;
    var num  = b.querySelector('.chap-num').textContent;
    var name = b.querySelector('.chap-name-input').value || ('Chapitre ' + num);
    var rows = [], sub = 0, idx = 0;
    var tb   = document.getElementById('tb-' + cid);
    if (tb) tb.querySelectorAll('tr').forEach(function(tr) {
      idx++;
      var ti = tr.querySelectorAll('input[type="text"]');
      var ni = tr.querySelectorAll('input[type="number"]');
      var si = tr.querySelectorAll('select');
      if (ti.length && ni.length >= 2) {
        var q = parseFloat(ni[0].value) || 0, p = parseFloat(ni[1].value) || 0;
        var m = q * p; sub += m;
        rows.push({ num: idx, desig: ti[0].value, unite: si.length ? si[0].value : 'ml', qty: q, pu: p, montant: m });
      }
    });
    grandHT += sub;
    chaps.push({ num: num, name: name, rows: rows, subtotal: sub });
  });
  var tva  = parseInt(document.getElementById('p-tva').value) || 0;
  var tvaV = grandHT * tva / 100;
  return {
    id:       Date.now(),
    nom:      document.getElementById('p-nom').value    || 'Projet sans titre',
    mo:       document.getElementById('p-mo').value,
    wilaya:   document.getElementById('p-wilaya').value,
    ref:      document.getElementById('p-ref').value,
    date:     document.getElementById('p-date').value,
    tva:      tva,
    be:       document.getElementById('p-be').value,
    statut:   document.getElementById('p-statut').value,
    objet:    document.getElementById('p-objet').value,
    sig1:     { nom: document.getElementById('s1n').value, titre: document.getElementById('s1t').value },
    sig2:     { nom: document.getElementById('s2n').value, titre: document.getElementById('s2t').value },
    sig3:     { nom: document.getElementById('s3n').value, titre: document.getElementById('s3t').value },
    chapitres: chaps,
    ht:        grandHT,
    tvaVal:    tvaV,
    ttc:       grandHT + tvaV,
    modifiedAt: new Date().toLocaleDateString('fr-DZ'),
  };
}

/* ── saveProject — corrigé : met à jour projects[] après sauvegarde cloud ── */
async function saveProject() {
  var d = collectData();
  if (!d.nom || d.nom === 'Projet sans titre') { notify('⚠ Saisissez un nom de projet'); return; }

  var isEdit = (editingIndex >= 0 && editingIndex < projects.length);

  if (isCloudMode()) {
    notify('☁ Sauvegarde cloud...');
    try {
      var ok = await supaInsertProject(d);
      if (ok) {
        /* Mettre à jour le tableau local projects[] */
        if (isEdit) {
          projects[editingIndex] = d;
        } else {
          projects.unshift(d);
        }
        document.getElementById('nb-projects').textContent = projects.length;
        notify('✓ Sauvegardé dans le cloud !');
        addAct('☁ Cloud saved', '"' + d.nom + '"', 'g');
      } else {
        notify('⚠ Erreur cloud — réessayez');
      }
    } catch(e) {
      notify('⚠ Erreur réseau — vérifiez votre connexion');
    }
  } else {
    /* Mode local */
    if (isEdit) {
      projects[editingIndex] = d;
    } else {
      projects.unshift(d);
    }
    localStorage.setItem('bq_v3', JSON.stringify(projects));
    document.getElementById('nb-projects').textContent = projects.length;
    notify('✓ Sauvegardé localement');
  }

  editingIndex = -1;
  setTimeout(function() { nav('projects', null); }, 700);
}

function resetForm() {
  ['p-nom','p-mo','p-ref','p-be','p-objet','s1n','s1t','s2n','s2t','s3n','s3t'].forEach(function(id) {
    var e = document.getElementById(id); if (e) e.value = '';
  });
  document.getElementById('p-wilaya').value = '';
  document.getElementById('p-statut').value = 'brouillon';
  document.getElementById('p-tva').value    = '19';
  document.getElementById('p-date').value   = new Date().toISOString().split('T')[0];
  document.getElementById('chaps-container').innerHTML = '';
  chapCounter  = 0;
  rowCounters  = {};
  selectedChap = null;
  document.getElementById('chaps-recap').innerHTML = '';
  ['t-ht','t-tva','t-ttc'].forEach(function(id) { document.getElementById(id).textContent = '0 DA'; });
  editingIndex = -1;
  addChap('Chapitre I — Travaux Préparatoires');
}

/* ════════════════════════════════════════════
   DASHBOARD — corrigé : utilise projects[] déjà chargé
════════════════════════════════════════════ */
function renderDash() {
  /* Mode local : re-lire le localStorage */
  if (!isCloudMode()) {
    projects = JSON.parse(localStorage.getItem('bq_v3') || '[]');
  }
  document.getElementById('s-total').textContent   = projects.length;
  document.getElementById('s-encours').textContent = projects.filter(function(p) { return p.statut === 'en-cours'; }).length;
  var ht = projects.reduce(function(s, p) { return s + (p.ht || 0); }, 0);
  document.getElementById('s-montant').textContent = ht > 1e6 ? (ht / 1e6).toFixed(2) + 'M' : fmtN(ht);
  document.getElementById('nb-projects').textContent = projects.length;
  var c = document.getElementById('dash-projects');
  if (!projects.length) {
    c.innerHTML = '<div class="empty"><div class="empty-icon">📋</div><h3>Aucun projet</h3><p>Créez votre premier DQE</p></div>';
    return;
  }
  var h = '<table><thead><tr><th>Projet</th><th>Chapitres</th><th>Montant HT</th><th>Statut</th><th>Date</th></tr></thead><tbody>';
  projects.slice(0, 5).forEach(function(p) {
    h += '<tr onclick="nav(\'projects\',null)">' +
      '<td>' + p.nom + '</td>' +
      '<td style="color:var(--text3);">' + (p.chapitres ? p.chapitres.length : 0) + ' chap.</td>' +
      '<td style="color:var(--accent);font-weight:600;">' + fmtN(p.ht || 0) + ' DA</td>' +
      '<td><span class="pill pill-' + p.statut + '">' + p.statut + '</span></td>' +
      '<td>' + p.modifiedAt + '</td>' +
      '</tr>';
  });
  c.innerHTML = h + '</tbody></table>';
}

function renderProjects() {
  if (isCloudMode()) {
    supaGetProjects().then(function(rows) {
      if (rows && Array.isArray(rows)) projects = rows;
      _doRenderProjects();
    }).catch(function() { _doRenderProjects(); });
    return;
  }
  projects = JSON.parse(localStorage.getItem('bq_v3') || '[]');
  _doRenderProjects();
}

function _doRenderProjects() {
  var c = document.getElementById('projects-container');
  if (!projects.length) {
    c.innerHTML = '<div class="empty"><div class="empty-icon">📂</div><h3>Aucun projet</h3></div>';
    return;
  }
  var h = '<div class="card"><div class="card-header"><div><h3>Tous les projets (' + projects.length + ')</h3></div>' +
    '<div style="display:flex;gap:8px;">' +
      '<button class="btn btn-ghost btn-sm" style="color:var(--red);" onclick="cleanDuplicates()">🧹 Nettoyer doublons</button>' +
      '<button class="btn btn-primary btn-sm" onclick="nav(\'new-project\',null)">+ Nouveau</button>' +
    '</div></div>' +
    '<table><thead><tr><th>Intitulé</th><th>Wilaya</th><th>Chapitres</th><th>Total HT</th><th>TVA</th><th>Total TTC</th><th>Statut</th><th>Date</th><th></th></tr></thead><tbody>';
  projects.forEach(function(p, i) {
    h += '<tr>' +
      '<td style="font-weight:600;cursor:pointer;" onclick="editProject(' + i + ')" title="Modifier">' + p.nom + '</td>' +
      '<td>' + (p.wilaya || '—') + '</td>' +
      '<td style="color:var(--text3);">' + (p.chapitres ? p.chapitres.length : 0) + '</td>' +
      '<td style="color:var(--accent);font-weight:600;">' + fmtN(p.ht || 0) + ' DA</td>' +
      '<td>' + p.tva + '%</td>' +
      '<td style="color:var(--green);font-weight:600;">' + fmtN(p.ttc || 0) + ' DA</td>' +
      '<td><span class="pill pill-' + p.statut + '">' + p.statut + '</span></td>' +
      '<td>' + p.modifiedAt + '</td>' +
      '<td style="display:flex;gap:5px;flex-wrap:wrap;">' +
        '<button class="btn btn-ghost btn-sm" style="color:var(--accent);" onclick="editProject(' + i + ')">✏ Modifier</button>' +
        '<button class="btn btn-ghost btn-sm" onclick="genPDF(' + i + ')">PDF</button>' +
        '<button class="btn btn-ghost btn-sm" style="color:var(--green)" onclick="genXLSX(' + i + ')">XLS</button>' +
        '<button class="btn btn-danger btn-sm" onclick="delProj(' + i + ')">✕</button>' +
      '</td>' +
      '</tr>';
  });
  c.innerHTML = h + '</tbody></table></div>';
}

/* ── delProj — corrigé : utilise supaDeleteProject() ── */
function delProj(i) {
  if (confirm('Supprimer ?')) {
    var p = projects[i];
    projects.splice(i, 1);

    if (isCloudMode() && p && p.id) {
      supaDeleteProject(String(p.id)).catch(function(e) { console.warn('Cloud delete error:', e); });
    } else {
      localStorage.setItem('bq_v3', JSON.stringify(projects));
    }

    document.getElementById('nb-projects').textContent = projects.length;
    renderProjects();
    notify('Projet supprimé');
  }
}

/* ── cleanDuplicates — corrigé : utilise Workers API ── */
async function cleanDuplicates() {
  if (!confirm('Supprimer tous les doublons ? (garde le plus récent de chaque projet)')) return;
  notify('🧹 Nettoyage en cours...');

  var seen   = {};
  var unique = [];
  projects.forEach(function(p) {
    if (!seen[p.nom]) { seen[p.nom] = true; unique.push(p); }
  });
  projects = unique;

  if (isCloudMode()) {
    /* Supprimer tout puis re-insérer les uniques */
    for (var i = 0; i < projects.length; i++) {
      await supaInsertProject(projects[i]);
    }
  } else {
    localStorage.setItem('bq_v3', JSON.stringify(projects));
  }

  document.getElementById('nb-projects').textContent = projects.length;
  renderProjects();
  notify('✓ Doublons supprimés — ' + projects.length + ' projets conservés');
}

function editProject(idx) {
  var p = projects[idx];
  if (!p) return;
  editingIndex = idx;
  resetForm();
  nav('new-project', null);
  setTimeout(function() {
    var flds = {
      'p-nom': p.nom || '', 'p-mo': p.mo || '', 'p-ref': p.ref || '',
      'p-be': p.be || '', 'p-objet': p.objet || '',
      's1n': p.sig1 && p.sig1.nom   ? p.sig1.nom   : '',
      's1t': p.sig1 && p.sig1.titre ? p.sig1.titre : '',
      's2n': p.sig2 && p.sig2.nom   ? p.sig2.nom   : '',
      's2t': p.sig2 && p.sig2.titre ? p.sig2.titre : '',
      's3n': p.sig3 && p.sig3.nom   ? p.sig3.nom   : '',
      's3t': p.sig3 && p.sig3.titre ? p.sig3.titre : '',
    };
    Object.keys(flds).forEach(function(id) { var el = document.getElementById(id); if (el) el.value = flds[id]; });
    if (p.wilaya) document.getElementById('p-wilaya').value = p.wilaya;
    if (p.statut) document.getElementById('p-statut').value = p.statut;
    if (p.tva !== undefined) document.getElementById('p-tva').value = String(p.tva);
    if (p.date)   document.getElementById('p-date').value   = p.date;
    document.getElementById('chaps-container').innerHTML = '';
    chapCounter = 0; rowCounters = {}; selectedChap = null;
    (p.chapitres || []).forEach(function(ch) {
      addChap(ch.name || (ch.num ? 'Chapitre ' + ch.num : 'Chapitre'));
      var cid = 'c' + chapCounter;
      var tb  = document.getElementById('tb-' + cid);
      if (tb) tb.innerHTML = '';
      rowCounters[cid] = 0;
      (ch.rows || []).forEach(function(r) { addRow(cid, r.desig, r.unite, r.pu, r.qty); });
    });
    recalcAll();
    document.getElementById('page-title').textContent = 'Modifier : ' + p.nom;
    document.getElementById('page-sub').textContent   = 'Modifiez puis cliquez Enregistrer';
    notify('✏ Projet chargé — modifiez et enregistrez');
  }, 200);
}

/* ════════════════════════════════════════════
   PDF BTPH
════════════════════════════════════════════ */
function generatePDF() { saveProject(); setTimeout(function() { genPDF(0); }, 400); }
function genPDF(idx) {
  var p = projects[idx];
  if (!p) { notify('Erreur'); return; }
  notify('Génération PDF BTPH...');
  var now   = new Date().toLocaleDateString('fr-DZ');
  var chaps = p.chapitres || [];

  var C = {
    PAGE : 'width:690px;margin:0 auto;font-family:Arial,sans-serif;font-size:9pt;color:#111;background:#fff;padding:20px;box-sizing:border-box;',
    BREAK: 'page-break-after:always;',
    hdr: function() {
      return '<table width="100%" cellpadding="0" cellspacing="0" style="border-bottom:2px solid #c8a800;margin-bottom:14px;padding-bottom:8px;"><tr>' +
        '<td style="vertical-align:middle;"><table cellpadding="0" cellspacing="4"><tr>' +
          '<td style="width:34px;height:34px;background:#f5d800;border-radius:6px;text-align:center;font-weight:900;font-size:13px;color:#0d1117;vertical-align:middle;">BQ</td>' +
          '<td style="padding-left:8px;"><div style="font-size:12pt;font-weight:900;color:#111;">BuildQuant</div><div style="font-size:7pt;color:#888;">Plateforme de Métré BTP — Algérie | BCR 2024</div></td>' +
        '</tr></table></td>' +
        '<td style="text-align:right;font-size:8pt;color:#666;vertical-align:middle;">Réf : <b>' + (p.ref || '—') + '</b><br/>Date : <b>' + (p.date || now) + '</b></td>' +
      '</tr></table>';
    },
    sec: function(t) {
      return '<table width="100%" cellpadding="0" cellspacing="0" style="margin:14px 0 8px;"><tr>' +
        '<td style="background:#0d1117;color:#f5d800;padding:7px 12px;font-size:8pt;font-weight:700;text-transform:uppercase;letter-spacing:.8px;border-radius:3px;">' + t + '</td>' +
      '</tr></table>';
    },
    pgF: function(n) {
      return '<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:16px;border-top:1px solid #e0e0e0;padding-top:8px;"><tr>' +
        '<td style="font-size:7pt;color:#aaa;">BuildQuant · DQE BTPH · ' + (p.nom || 'Projet') + '</td>' +
        '<td style="text-align:right;font-size:7pt;color:#aaa;">Page ' + n + '</td>' +
      '</tr></table>';
    },
    sig: function(t, sg) {
      return '<td width="33%" style="padding:4px;vertical-align:top;">' +
        '<table width="100%" cellpadding="6" cellspacing="0" style="border:1px solid #ddd;border-radius:4px;font-size:8pt;">' +
          '<tr><td style="font-size:7pt;color:#888;text-transform:uppercase;border-bottom:1px solid #eee;font-weight:700;">' + t + '</td></tr>' +
          '<tr><td style="font-size:9pt;font-weight:600;color:#111;">' + (sg && sg.nom ? sg.nom : '&nbsp;') + '</td></tr>' +
          '<tr><td style="font-size:8pt;color:#555;">' + (sg && sg.titre ? sg.titre : '&nbsp;') + '</td></tr>' +
          '<tr><td style="height:55px;border:1.5px dashed #ddd;text-align:center;color:#ccc;font-size:8pt;border-radius:3px;">Signature / Cachet</td></tr>' +
        '</table>' +
      '</td>';
    },
    TH : 'background:#0d1117;color:#f5d800;padding:6px 8px;font-size:7.5pt;font-weight:700;border:1px solid #0d1117;',
    TD : 'padding:5px 8px;border:1px solid #e0e0e0;font-size:8.5pt;color:#222;',
    TDR: 'padding:5px 8px;border:1px solid #e0e0e0;font-size:8.5pt;color:#222;text-align:right;',
    TDB: 'padding:5px 8px;border:1px solid #e0e0e0;font-size:8.5pt;font-weight:700;color:#c8a800;text-align:right;',
  };

  var cover =
    '<div style="' + C.PAGE + C.BREAK + '">' +
    '<table width="100%" cellpadding="0" cellspacing="0" style="border:3px solid #c8a800;border-radius:6px;padding:28px;"><tr><td>' +
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:30px;"><tr>' +
        '<td><table cellpadding="0" cellspacing="6"><tr>' +
          '<td style="width:48px;height:48px;background:#f5d800;border-radius:10px;text-align:center;font-weight:900;font-size:19px;color:#0d1117;vertical-align:middle;">BQ</td>' +
          '<td style="padding-left:10px;"><div style="font-size:18pt;font-weight:900;color:#111;">BuildQuant</div><div style="font-size:8pt;color:#888;text-transform:uppercase;letter-spacing:1px;">Plateforme de Métré BTP</div></td>' +
        '</tr></table></td>' +
        '<td style="text-align:right;font-size:8.5pt;color:#555;vertical-align:top;">Réf : <b>' + (p.ref || '—') + '</b><br/>' + now + '</td>' +
      '</tr></table>' +
      '<table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;"><tr><td style="text-align:center;">' +
        '<div style="font-size:8.5pt;color:#888;text-transform:uppercase;letter-spacing:2px;margin-bottom:6px;">République Algérienne Démocratique et Populaire</div>' +
        '<div style="font-size:8.5pt;color:#777;margin-bottom:18px;">' + (p.mo || "Maître d'Ouvrage") + '</div>' +
        '<table width="60%" cellpadding="12" cellspacing="0" align="center" style="border:2.5px solid #c8a800;border-radius:6px;"><tr><td style="text-align:center;">' +
          '<div style="font-size:9pt;color:#888;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;">Devis Quantitatif et Estimatif</div>' +
          '<div style="font-size:17pt;font-weight:900;color:#111;line-height:1.2;">' + (p.nom || 'Projet') + '</div>' +
          (p.objet ? '<div style="font-size:8pt;color:#555;margin-top:6px;font-style:italic;">' + p.objet + '</div>' : '') +
        '</td></tr></table>' +
      '</td></tr></table>' +
      '<table width="70%" cellpadding="6" cellspacing="0" align="center" style="border:1px solid #ddd;border-radius:4px;margin-bottom:20px;">' +
        [['Wilaya', p.wilaya||'—'],['Chapitres', chaps.length+' chapitres'],["Maître d'ouvrage", p.mo||'—'],["Bureau d'études", p.be||'—'],['Réf. dossier', p.ref||'—'],['Date', p.date||now]].map(function(r) {
          return '<tr><td width="40%" style="background:#f5f5f5;font-size:8pt;font-weight:600;color:#555;border-bottom:1px solid #eee;border-right:1px solid #eee;">' + r[0] + '</td><td style="font-size:8.5pt;border-bottom:1px solid #eee;">' + r[1] + '</td></tr>';
        }).join('') +
      '</table>' +
      '<table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #eee;padding-top:12px;"><tr>' +
        '<td style="font-size:8pt;color:#aaa;">Généré par BuildQuant · BCR MHUV Algérie 2024</td>' +
        '<td style="text-align:right;"><span style="background:#0d1117;color:#f5d800;padding:5px 14px;border-radius:4px;font-size:9pt;font-weight:700;">CONFIDENTIEL</span></td>' +
      '</tr></table>' +
    '</td></tr></table></div>';

  var toc =
    '<div style="' + C.PAGE + C.BREAK + '">' + C.hdr() + C.sec('Table des Matières — Sommaire DQE') +
    '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:9pt;margin-bottom:16px;">' +
      '<thead><tr>' +
        '<th width="6%" style="' + C.TH + 'text-align:center;">N°</th>' +
        '<th style="' + C.TH + 'text-align:left;">Chapitre</th>' +
        '<th width="12%" style="' + C.TH + 'text-align:center;">Articles</th>' +
        '<th width="22%" style="' + C.TH + 'text-align:right;">Sous-total HT</th>' +
      '</tr></thead><tbody>' +
      chaps.map(function(ch, i) {
        return '<tr style="background:' + (i%2===0 ? '#fff' : '#fafafa') + '">' +
          '<td style="' + C.TD + 'text-align:center;">' + (i+1) + '</td>' +
          '<td style="' + C.TD + 'font-weight:600;">Chap. ' + ch.num + ' — ' + ch.name + '</td>' +
          '<td style="' + C.TD + 'text-align:center;">' + (ch.rows ? ch.rows.length : 0) + '</td>' +
          '<td style="' + C.TDB + '">' + fmtN(ch.subtotal || 0) + ' DA</td>' +
        '</tr>';
      }).join('') +
      '<tr style="background:#fffbea;"><td colspan="3" style="' + C.TD + 'font-weight:700;text-align:right;">TOTAL GÉNÉRAL HT</td>' +
      '<td style="' + C.TDB + 'font-size:10pt;">' + fmtN(p.ht || 0) + ' DA</td></tr>' +
    '</tbody></table>' +
    '<table width="100%" cellpadding="0" cellspacing="8" style="margin-top:4px;"><tr>' +
      '<td width="50%" style="vertical-align:top;">' +
        '<table width="100%" cellpadding="8" cellspacing="0" style="background:#f9f9f9;border:1px solid #ddd;border-radius:4px;font-size:9pt;">' +
          '<tr><td colspan="2" style="font-size:7pt;color:#888;text-transform:uppercase;font-weight:700;border-bottom:1px solid #eee;padding-bottom:6px;">Récapitulatif financier</td></tr>' +
          '<tr><td style="color:#555;padding:4px 0;">Montant HT</td><td style="text-align:right;font-weight:600;">' + fmtN(p.ht||0) + ' DA</td></tr>' +
          '<tr><td style="color:#555;padding:4px 0;">TVA (' + p.tva + '%)</td><td style="text-align:right;">' + fmtN(p.tvaVal||0) + ' DA</td></tr>' +
          '<tr style="border-top:2px solid #c8a800;"><td style="font-weight:700;padding-top:6px;">MONTANT TTC</td><td style="text-align:right;font-weight:700;color:#c8a800;font-size:11pt;">' + fmtN(p.ttc||0) + ' DA</td></tr>' +
        '</table>' +
      '</td>' +
      '<td width="50%" style="vertical-align:top;padding-left:8px;">' +
        '<table width="100%" cellpadding="8" cellspacing="0" style="background:#f9f9f9;border:1px solid #ddd;border-radius:4px;font-size:8.5pt;">' +
          '<tr><td colspan="2" style="font-size:7pt;color:#888;text-transform:uppercase;font-weight:700;border-bottom:1px solid #eee;padding-bottom:6px;">Informations projet</td></tr>' +
          "<tr><td style='color:#555;padding:3px 0;'>Maître d'ouvrage</td><td style='text-align:right;'>" + (p.mo||'—') + '</td></tr>' +
          '<tr><td style="color:#555;padding:3px 0;">Wilaya</td><td style="text-align:right;">' + (p.wilaya||'—') + '</td></tr>' +
          "<tr><td style='color:#555;padding:3px 0;'>Bureau d'études</td><td style='text-align:right;'>" + (p.be||'—') + '</td></tr>' +
        '</table>' +
      '</td>' +
    '</tr></table>' +
    C.pgF(2) + '</div>';

  var chapPages = chaps.map(function(ch, ci) {
    var rows = (ch.rows || []).map(function(r, ri) {
      var bg = ri%2===0 ? '#fff' : '#fafafa';
      return '<tr style="background:' + bg + '">' +
        '<td style="' + C.TD + 'text-align:center;width:28px;">' + (ri+1) + '</td>' +
        '<td style="' + C.TD + '">' + r.desig + '</td>' +
        '<td style="' + C.TD + 'text-align:center;width:40px;">' + r.unite + '</td>' +
        '<td style="' + C.TDR + 'width:55px;">' + r.qty + '</td>' +
        '<td style="' + C.TDR + 'width:90px;">' + fmtN(r.pu) + ' DA</td>' +
        '<td style="' + C.TDB + 'width:100px;">' + fmtN(r.montant) + ' DA</td>' +
      '</tr>';
    }).join('');
    return '<div style="' + C.PAGE + C.BREAK + '">' + C.hdr() + C.sec('Chapitre ' + ch.num + ' — ' + ch.name) +
      '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:9pt;margin-bottom:10px;">' +
        '<thead><tr>' +
          '<th width="4%" style="' + C.TH + 'text-align:center;">N°</th>' +
          '<th style="' + C.TH + 'text-align:left;">Désignation des Travaux</th>' +
          '<th width="6%" style="' + C.TH + 'text-align:center;">Unité</th>' +
          '<th width="8%" style="' + C.TH + 'text-align:center;">Qté</th>' +
          '<th width="13%" style="' + C.TH + 'text-align:right;">P.U. (DA)</th>' +
          '<th width="14%" style="' + C.TH + 'text-align:right;">Montant HT</th>' +
        '</tr></thead>' +
        '<tbody>' + (rows || '<tr><td colspan="6" style="' + C.TD + 'text-align:center;color:#aaa;">Aucun article</td></tr>') + '</tbody>' +
        '<tfoot><tr style="background:#fffbea;">' +
          '<td colspan="5" style="' + C.TD + 'font-weight:700;text-align:right;">Sous-total Chapitre ' + ch.num + '</td>' +
          '<td style="' + C.TDB + '">' + fmtN(ch.subtotal || 0) + ' DA</td>' +
        '</tr></tfoot>' +
      '</table>' + C.pgF(3 + ci) + '</div>';
  }).join('');

  var recap =
    '<div style="' + C.PAGE + '">' + C.hdr() + C.sec('Récapitulatif Général DQE') +
    '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;font-size:9pt;margin-bottom:16px;">' +
      '<thead><tr>' +
        '<th width="7%" style="' + C.TH + 'text-align:center;">Chap.</th>' +
        '<th style="' + C.TH + 'text-align:left;">Désignation</th>' +
        '<th width="9%" style="' + C.TH + 'text-align:center;">Art.</th>' +
        '<th width="20%" style="' + C.TH + 'text-align:right;">Montant HT</th>' +
      '</tr></thead>' +
      '<tbody>' +
      chaps.map(function(ch, i) {
        return '<tr style="background:' + (i%2===0 ? '#fff' : '#fafafa') + '">' +
          '<td style="' + C.TD + 'text-align:center;">' + ch.num + '</td>' +
          '<td style="' + C.TD + 'font-weight:600;">' + ch.name + '</td>' +
          '<td style="' + C.TD + 'text-align:center;">' + (ch.rows ? ch.rows.length : 0) + '</td>' +
          '<td style="' + C.TDB + '">' + fmtN(ch.subtotal || 0) + ' DA</td>' +
        '</tr>';
      }).join('') +
      '</tbody>' +
      '<tfoot>' +
        '<tr style="background:#f5f5f5;"><td colspan="3" style="' + C.TD + 'font-weight:700;text-align:right;">TOTAL HT</td><td style="' + C.TDB + '">' + fmtN(p.ht||0) + ' DA</td></tr>' +
        '<tr><td colspan="3" style="' + C.TD + 'text-align:right;color:#555;">TVA (' + p.tva + '%)</td><td style="' + C.TDR + '">' + fmtN(p.tvaVal||0) + ' DA</td></tr>' +
        '<tr><td colspan="3" style="padding:10px 8px;font-weight:900;font-size:11pt;background:#0d1117;color:#f5d800;text-align:right;border:1px solid #0d1117;">MONTANT TOTAL TTC</td>' +
             '<td style="padding:10px 8px;font-weight:900;font-size:11pt;background:#0d1117;color:#f5d800;text-align:right;border:1px solid #0d1117;">' + fmtN(p.ttc||0) + ' DA</td></tr>' +
      '</tfoot>' +
    '</table>' +
    C.sec('Signatures et Visas Officiels') +
    '<table width="100%" cellpadding="0" cellspacing="0" style="margin-top:8px;"><tr>' +
      C.sig('Établi par', p.sig1) + C.sig('Vérifié par', p.sig2) + C.sig('Approuvé par', p.sig3) +
    '</tr></table>' +
    C.pgF(3 + chaps.length) + '</div>';

  var src = document.getElementById('pdf-src');
  src.innerHTML = cover + toc + chapPages + recap;
  src.style.cssText = 'display:block;position:fixed;top:0;left:-9999px;width:730px;background:#fff;font-family:Arial,sans-serif;';

  var opt = {
    margin:      0,
    filename:    'BQ_DQE_' + (p.nom || 'DQE').replace(/\s+/g,'_').substring(0,40) + '.pdf',
    image:       { type:'jpeg', quality:.97 },
    html2canvas: { scale:2, useCORS:true, windowWidth:730, scrollX:0, scrollY:0, logging:false },
    jsPDF:       { unit:'mm', format:'a4', orientation:'portrait' },
    pagebreak:   { mode:'avoid-all', before:'div[style*="page-break-after"]' }
  };

  html2pdf().set(opt).from(src).save().then(function() {
    src.style.cssText = 'display:none;';
    src.innerHTML     = '';
    notify('✓ PDF BTPH exporté !');
    addAct('PDF exporté', '"' + (p.nom || 'Projet') + '"', 'y');
  });
}

/* ════════════════════════════════════════════
   XLSX EXPORT ENGINE
════════════════════════════════════════════ */
function generateXLSX() { saveProject(); setTimeout(function() { genXLSX(0); }, 400); }

async function genXLSX(idx) {
  var p = projects[idx];
  if (!p) { notify('Erreur: projet introuvable'); return; }
  notify('📊 Génération Excel...');
  var now   = new Date().toLocaleDateString('fr-DZ');
  var chaps = p.chapitres || [];
  var strings = [], strMap = {};
  function si(s) {
    s = String(s || '');
    if (s in strMap) return strMap[s];
    var i = strings.length; strMap[s] = i; strings.push(s); return i;
  }
  var STYLES = buildStyleSheet();
  var sheets = [];

  var covRows = [];
  function addCovRow(cells) { covRows.push(cells); }
  addCovRow([{t:'s',v:si('BuildQuant — Plateforme de Métré BTP'),s:1,w:200}]);
  addCovRow([{t:'s',v:si('BCR MHUV Algérie 2024'),s:0}]);
  addCovRow([]);
  addCovRow([{t:'s',v:si('DEVIS QUANTITATIF ET ESTIMATIF (DQE)'),s:1}]);
  addCovRow([{t:'s',v:si(p.nom||'Projet'),s:1}]);
  addCovRow([]);
  addCovRow([{t:'s',v:si("Maître d'ouvrage"),s:4},{t:'s',v:si(p.mo||'—'),s:5},{t:'s',v:si('Wilaya'),s:4},{t:'s',v:si(p.wilaya||'—'),s:5}]);
  addCovRow([{t:'s',v:si("Bureau d'études"),s:4},{t:'s',v:si(p.be||'—'),s:5},{t:'s',v:si('Réf. dossier'),s:4},{t:'s',v:si(p.ref||'—'),s:5}]);
  addCovRow([{t:'s',v:si('Date'),s:4},{t:'s',v:si(p.date||now),s:5},{t:'s',v:si('TVA'),s:4},{t:'s',v:si(p.tva+'%'),s:5}]);
  addCovRow([{t:'s',v:si('Statut'),s:4},{t:'s',v:si(p.statut||'—'),s:5},{t:'s',v:si('Objet'),s:4},{t:'s',v:si(p.objet||'—'),s:5}]);
  addCovRow([]);
  addCovRow([{t:'s',v:si('SYNTHÈSE FINANCIÈRE'),s:1}]);
  addCovRow([{t:'s',v:si('Montant Total HT'),s:4},{t:'n',v:p.ht||0,s:7}]);
  addCovRow([{t:'s',v:si('TVA ('+p.tva+'%)'),s:4},{t:'n',v:p.tvaVal||0,s:6}]);
  addCovRow([{t:'s',v:si('MONTANT TOTAL TTC'),s:3},{t:'n',v:p.ttc||0,s:3}]);
  addCovRow([]);
  addCovRow([{t:'s',v:si('CHAPITRES DQE'),s:1}]);
  chaps.forEach(function(ch) { addCovRow([{t:'s',v:si('Chapitre '+ch.num+' — '+ch.name),s:5},{t:'n',v:ch.subtotal||0,s:2}]); });
  addCovRow([]);
  addCovRow([{t:'s',v:si('Établi: '+(p.sig1&&p.sig1.nom?p.sig1.nom:'—')+' | Vérifié: '+(p.sig2&&p.sig2.nom?p.sig2.nom:'—')+' | Approuvé: '+(p.sig3&&p.sig3.nom?p.sig3.nom:'—')),s:0}]);
  addCovRow([{t:'s',v:si('Généré par BuildQuant · '+now),s:0}]);
  sheets.push({name:'Couverture', rows:covRows, cols:[{w:32},{w:36},{w:18},{w:18}]});

  chaps.forEach(function(ch) {
    var rows = [];
    rows.push([{t:'s',v:si('BuildQuant · DQE BTPH · '+p.nom),s:0},{t:'s',v:si(''),s:0},{t:'s',v:si(''),s:0},{t:'s',v:si(''),s:0},{t:'s',v:si('Réf: '+(p.ref||'—')),s:0},{t:'s',v:si(p.date||now),s:0}]);
    rows.push([]);
    rows.push([{t:'s',v:si('Chapitre '+ch.num+' — '+ch.name),s:1},{t:'s',v:si(''),s:1},{t:'s',v:si(''),s:1},{t:'s',v:si(''),s:1},{t:'s',v:si(''),s:1},{t:'s',v:si(''),s:1}]);
    rows.push([]);
    rows.push([{t:'s',v:si('N°'),s:1},{t:'s',v:si('Désignation des Travaux'),s:1},{t:'s',v:si('Unité'),s:1},{t:'s',v:si('Quantité'),s:1},{t:'s',v:si('P.U. (DA)'),s:1},{t:'s',v:si('Montant HT (DA)'),s:1}]);
    (ch.rows||[]).forEach(function(r,ri) {
      var alt = ri%2===1;
      rows.push([{t:'n',v:r.num,s:alt?8:0},{t:'s',v:si(r.desig),s:alt?8:5},{t:'s',v:si(r.unite),s:alt?8:5},{t:'n',v:r.qty,s:alt?9:6},{t:'n',v:r.pu,s:alt?9:6},{t:'n',v:r.montant,s:alt?9:7}]);
    });
    rows.push([{t:'s',v:si(''),s:2},{t:'s',v:si(''),s:2},{t:'s',v:si(''),s:2},{t:'s',v:si(''),s:2},{t:'s',v:si('Sous-total '+ch.name),s:2},{t:'n',v:ch.subtotal||0,s:2}]);
    rows.push([]);
    rows.push([{t:'s',v:si("Maître d'ouvrage :"),s:4},{t:'s',v:si(p.mo||'—'),s:5},{t:'s',v:si(''),s:0},{t:'s',v:si('Wilaya :'),s:4},{t:'s',v:si(p.wilaya||'—'),s:5}]);
    var sn = ('Chap.'+ch.num+' '+ch.name).substring(0,31);
    sheets.push({name:sn, rows:rows, cols:[{w:6},{w:50},{w:8},{w:12},{w:18},{w:20}]});
  });

  var rRows = [];
  rRows.push([{t:'s',v:si('BuildQuant · DQE BTPH · '+p.nom),s:0},{t:'s',v:si(''),s:0},{t:'s',v:si(''),s:0},{t:'s',v:si('Réf: '+(p.ref||'—')),s:0}]);
  rRows.push([]);
  rRows.push([{t:'s',v:si('RÉCAPITULATIF GÉNÉRAL — DQE'),s:1},{t:'s',v:si(''),s:1},{t:'s',v:si(''),s:1},{t:'s',v:si(''),s:1}]);
  rRows.push([]);
  rRows.push([{t:'s',v:si('Chap.'),s:1},{t:'s',v:si('Désignation'),s:1},{t:'s',v:si('Articles'),s:1},{t:'s',v:si('Sous-total HT (DA)'),s:1}]);
  chaps.forEach(function(ch,ci) {
    var alt = ci%2===1;
    rRows.push([{t:'s',v:si(ch.num),s:alt?8:5},{t:'s',v:si('Chap.'+ch.num+' — '+ch.name),s:alt?8:5},{t:'n',v:ch.rows?ch.rows.length:0,s:alt?8:5},{t:'n',v:ch.subtotal||0,s:alt?9:7}]);
  });
  rRows.push([]);
  rRows.push([{t:'s',v:si(''),s:0},{t:'s',v:si('TOTAL HT'),s:4},{t:'s',v:si(''),s:4},{t:'n',v:p.ht||0,s:2}]);
  rRows.push([{t:'s',v:si(''),s:0},{t:'s',v:si('TVA ('+p.tva+'%)'),s:5},{t:'s',v:si(''),s:5},{t:'n',v:p.tvaVal||0,s:6}]);
  rRows.push([{t:'s',v:si(''),s:0},{t:'s',v:si('MONTANT TOTAL TTC'),s:3},{t:'s',v:si(''),s:3},{t:'n',v:p.ttc||0,s:3}]);
  rRows.push([]);
  rRows.push([{t:'s',v:si('Établi par'),s:4},{t:'s',v:si('Vérifié par'),s:4},{t:'s',v:si(''),s:0},{t:'s',v:si('Approuvé par'),s:4}]);
  rRows.push([{t:'s',v:si(p.sig1&&p.sig1.nom?p.sig1.nom:'—'),s:5},{t:'s',v:si(p.sig2&&p.sig2.nom?p.sig2.nom:'—'),s:5},{t:'s',v:si(''),s:0},{t:'s',v:si(p.sig3&&p.sig3.nom?p.sig3.nom:'—'),s:5}]);
  rRows.push([{t:'s',v:si('Généré par BuildQuant · BCR MHUV Algérie 2024 · '+now),s:0}]);
  sheets.push({name:'Récapitulatif', rows:rRows, cols:[{w:10},{w:48},{w:12},{w:22}]});

  var blob = buildXLSX(sheets, strings, STYLES);
  var url  = URL.createObjectURL(blob);
  var a    = document.createElement('a');
  a.href   = url;
  a.download = 'BuildQuant_DQE_' + (p.nom||'DQE').replace(/[^a-zA-Z0-9_ -]/g,'').replace(/\s+/g,'_').substring(0,40) + '_' + now.replace(/\//g,'-') + '.xlsx';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  notify('✓ Excel exporté avec mise en page complète !');
  addAct('Excel exporté', '"' + (p.nom||'Projet') + '"', 'g');
}

/* ════════════════════════════════════════════
   XLSX BUILDER — Office Open XML natif
════════════════════════════════════════════ */
function buildStyleSheet() {
  return '<?xml version="1.0" encoding="UTF-8"?>' +
  '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
  '<fonts count="5">' +
    '<font><sz val="10"/><name val="Arial"/></font>' +
    '<font><sz val="10"/><b/><name val="Arial"/><color rgb="FFF5D800"/></font>' +
    '<font><sz val="10"/><b/><name val="Arial"/><color rgb="FFC8A800"/></font>' +
    '<font><sz val="11"/><b/><name val="Arial"/><color rgb="FFF5D800"/></font>' +
    '<font><sz val="9"/><b/><name val="Arial"/><color rgb="FF555555"/></font>' +
  '</fonts>' +
  '<fills count="6">' +
    '<fill><patternFill patternType="none"/></fill>' +
    '<fill><patternFill patternType="gray125"/></fill>' +
    '<fill><patternFill patternType="solid"><fgColor rgb="FF0D1117"/></patternFill></fill>' +
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFFFD8E"/></patternFill></fill>' +
    '<fill><patternFill patternType="solid"><fgColor rgb="FFF5F5F5"/></patternFill></fill>' +
    '<fill><patternFill patternType="solid"><fgColor rgb="FFFAFAFA"/></patternFill></fill>' +
  '</fills>' +
  '<borders count="3">' +
    '<border><left/><right/><top/><bottom/><diagonal/></border>' +
    '<border><left style="thin"><color rgb="FFCCCCCC"/></left><right style="thin"><color rgb="FFCCCCCC"/></right><top style="thin"><color rgb="FFCCCCCC"/></top><bottom style="thin"><color rgb="FFCCCCCC"/></bottom><diagonal/></border>' +
    '<border><left style="medium"><color rgb="FFC8A800"/></left><right style="medium"><color rgb="FFC8A800"/></right><top style="medium"><color rgb="FFC8A800"/></top><bottom style="medium"><color rgb="FFC8A800"/></bottom><diagonal/></border>' +
  '</borders>' +
  '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>' +
  '<cellXfs count="10">' +
    '<xf numFmtId="0"  fontId="0" fillId="0" borderId="0" xfId="0"/>' +
    '<xf numFmtId="0"  fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"><alignment horizontal="center" vertical="center"/></xf>' +
    '<xf numFmtId="4"  fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyNumberFormat="1"><alignment horizontal="right" vertical="center"/></xf>' +
    '<xf numFmtId="4"  fontId="3" fillId="2" borderId="2" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyNumberFormat="1"><alignment horizontal="right" vertical="center"/></xf>' +
    '<xf numFmtId="0"  fontId="4" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>' +
    '<xf numFmtId="0"  fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"><alignment wrapText="1"/></xf>' +
    '<xf numFmtId="4"  fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyNumberFormat="1"><alignment horizontal="right"/></xf>' +
    '<xf numFmtId="4"  fontId="2" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyNumberFormat="1"><alignment horizontal="right"/></xf>' +
    '<xf numFmtId="0"  fontId="0" fillId="5" borderId="1" xfId="0" applyFill="1" applyBorder="1"/>' +
    '<xf numFmtId="4"  fontId="0" fillId="5" borderId="1" xfId="0" applyFill="1" applyBorder="1" applyNumberFormat="1"><alignment horizontal="right"/></xf>' +
  '</cellXfs>' +
  '</styleSheet>';
}

function buildXLSX(sheets, strings, stylesXml) {
  var ssXml = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="' + strings.length + '" uniqueCount="' + strings.length + '">';
  strings.forEach(function(s) { ssXml += '<si><t xml:space="preserve">' + escXml(s) + '</t></si>'; });
  ssXml += '</sst>';

  var wbXml = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>';
  sheets.forEach(function(sh, i) { wbXml += '<sheet name="' + escXml(sh.name) + '" sheetId="' + (i+1) + '" r:id="rId' + (i+1) + '"/>'; });
  wbXml += '</sheets></workbook>';

  var wbRels = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
    '<Relationship Id="rId0" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>' +
    '<Relationship Id="rId999" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>';
  sheets.forEach(function(sh, i) { wbRels += '<Relationship Id="rId' + (i+1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + (i+1) + '.xml"/>'; });
  wbRels += '</Relationships>';

  var ctXml = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
    '<Default Extension="xml" ContentType="application/xml"/>' +
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
    '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>' +
    '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>';
  sheets.forEach(function(sh, i) { ctXml += '<Override PartName="/xl/worksheets/sheet' + (i+1) + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'; });
  ctXml += '</Types>';

  var rootRels = '<?xml version="1.0" encoding="UTF-8"?>' +
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>' +
    '</Relationships>';

  var parts = {};
  parts['[Content_Types].xml']        = ctXml;
  parts['_rels/.rels']                = rootRels;
  parts['xl/workbook.xml']            = wbXml;
  parts['xl/_rels/workbook.xml.rels'] = wbRels;
  parts['xl/styles.xml']              = stylesXml;
  parts['xl/sharedStrings.xml']       = ssXml;

  sheets.forEach(function(sh, si) {
    var xml = '<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">';
    if (sh.cols && sh.cols.length) {
      xml += '<cols>';
      sh.cols.forEach(function(col, ci) { xml += '<col min="' + (ci+1) + '" max="' + (ci+1) + '" width="' + col.w + '" customWidth="1"/>'; });
      xml += '</cols>';
    }
    xml += '<sheetData>';
    sh.rows.forEach(function(row, ri) {
      if (!row || !row.length) { xml += '<row r="' + (ri+1) + '"/>'; return; }
      xml += '<row r="' + (ri+1) + '">';
      row.forEach(function(cell, ci) {
        if (!cell) return;
        var col   = String.fromCharCode(65 + ci);
        var ref   = col + (ri+1);
        var sAttr = cell.s !== undefined ? ' s="' + cell.s + '"' : '';
        if (cell.t === 'n') { xml += '<c r="' + ref + '"' + sAttr + ' t="n"><v>' + (cell.v||0) + '</v></c>'; }
        else                { xml += '<c r="' + ref + '"' + sAttr + ' t="s"><v>' + (cell.v||0) + '</v></c>'; }
      });
      xml += '</row>';
    });
    xml += '</sheetData></worksheet>';
    parts['xl/worksheets/sheet' + (si+1) + '.xml'] = xml;
  });
  return zipFromParts(parts);
}

function escXml(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function zipFromParts(parts) {
  var entries = [], centralDir = [], offset = 0;
  function crc32(str) {
    var crc = 0xFFFFFFFF, bytes = new TextEncoder().encode(str);
    for (var i=0;i<bytes.length;i++) { crc ^= bytes[i]; for (var j=0;j<8;j++) crc = (crc>>>1)^(crc&1?0xEDB88320:0); }
    return (crc^0xFFFFFFFF)>>>0;
  }
  function u16(n) { return [n&0xFF,(n>>8)&0xFF]; }
  function u32(n) { return [n&0xFF,(n>>8)&0xFF,(n>>16)&0xFF,(n>>24)&0xFF]; }
  function strBytes(s) { return Array.from(new TextEncoder().encode(s)); }
  Object.keys(parts).forEach(function(name) {
    var data = strBytes(parts[name]), nameBytes = strBytes(name), crc = crc32(parts[name]), size = data.length;
    var lfh = [0x50,0x4B,0x03,0x04,20,0,0,0,0,0,0,0,0,0,...u32(crc),...u32(size),...u32(size),...u16(nameBytes.length),0,0,...nameBytes,...data];
    centralDir.push({name:nameBytes,crc:crc,size:size,offset:offset});
    entries.push(...lfh); offset += lfh.length;
  });
  var cdOffset = offset;
  centralDir.forEach(function(e) {
    var cde = [0x50,0x4B,0x01,0x02,20,0,20,0,0,0,0,0,0,0,0,0,...u32(e.crc),...u32(e.size),...u32(e.size),...u16(e.name.length),0,0,0,0,0,0,0,0,0,0,0,0,...u32(e.offset),...e.name];
    entries.push(...cde);
  });
  var cdSize = entries.length - cdOffset;
  var eocd = [0x50,0x4B,0x05,0x06,0,0,0,0,...u16(centralDir.length),...u16(centralDir.length),...u32(cdSize),...u32(cdOffset),0,0];
  entries.push(...eocd);
  return new Blob([new Uint8Array(entries)], {type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
}

/* ════════════════════════════════════════════
   EXCEL IMPORT
════════════════════════════════════════════ */
function handleExcelImport(e) {
  if (!selectedChap) { notify("⚠ Sélectionnez un chapitre d'abord"); e.target.value = ''; return; }
  var file = e.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(ev) {
    try {
      var wb   = XLSX.read(ev.target.result, {type:'binary'});
      var ws   = wb.Sheets[wb.SheetNames[0]];
      var rows = XLSX.utils.sheet_to_json(ws, {header:1});
      var inserted = 0, skipped = 0;
      for (var i=1; i<rows.length; i++) {
        var row = rows[i];
        if (!row || !row[0]) continue;
        var bcrCode = String(row[0]).trim().toUpperCase();
        var qty     = parseFloat(row[1]) || 1;
        var item    = BCR.find(function(b) { return b.id.toUpperCase() === bcrCode; });
        if (item) { var price = priceFor(item, activeZone); addRow(selectedChap, item.nom, item.u, price, qty); inserted++; }
        else       { addRow(selectedChap, String(row[0]).trim(), 'U', 0, qty); skipped++; }
      }
      notify('✓ Import terminé — ' + inserted + ' BCR insérés, ' + skipped + ' manuels');
    } catch(err) { notify('⚠ Erreur lecture fichier: ' + err.message); }
    e.target.value = '';
  };
  reader.readAsBinaryString(file);
}

/* ════════════════════════════════════════════
   UTILS
════════════════════════════════════════════ */
function fmtN(n) { return Math.round(n).toLocaleString('fr-DZ'); }
var ntimer;
function notify(msg) {
  var n = document.getElementById('notif');
  document.getElementById('notif-msg').textContent = msg;
  n.classList.add('show');
  clearTimeout(ntimer);
  ntimer = setTimeout(function() { n.classList.remove('show'); }, 2800);
}
function addAct(t, s, c) {
  var l   = document.getElementById('activity-list');
  var now = new Date().toLocaleTimeString('fr-DZ', {hour:'2-digit', minute:'2-digit'});
  var d   = document.createElement('div');
  d.className = 'act-item';
  d.innerHTML = '<div class="act-dot ' + (c||'y') + '"></div><div><div class="act-title">' + t + '</div><div class="act-sub">' + s + '</div></div><div class="act-time">' + now + '</div>';
  l.insertBefore(d, l.firstChild);
}

function setBN(activeId) {
  document.querySelectorAll('.bn-item').forEach(function(b) { b.classList.remove('active'); });
  if (!activeId) return;
  var el = document.getElementById(activeId);
  if (el) el.classList.add('active');
}

/* ════════════════════════════════════════════
   INIT
════════════════════════════════════════════ */
document.getElementById('p-date').value = new Date().toISOString().split('T')[0];
window.addEventListener('load', function() {
  waitForSupabase(function() { checkSession(); });
});

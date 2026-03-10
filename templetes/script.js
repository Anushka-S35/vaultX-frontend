// script.js
// Single JS for all pages. Uses localStorage for persistence and Web Crypto API for encryption (AES-GCM).
// Data layout (stored in localStorage key 'pv_users'):
// pv_users = [ { email, name, saltBase64, iterations, auth: {ct, iv}, entries: [ {id, site, user, pass: {ct,iv}} ] } ]

/* ---------------------- Utilities ---------------------- */
const utf8 = new TextEncoder();
const txtdec = new TextDecoder();

function bufToBase64(buffer){
  let bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}
function base64ToBuf(base64){
  let binary = atob(base64);
  let len = binary.length;
  let bytes = new Uint8Array(len);
  for (let i=0;i<len;i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
function randBytes(len){
  const a = new Uint8Array(len);
  crypto.getRandomValues(a);
  return a;
}

/* Derive AES-GCM key from password and salt */
async function deriveKeyFromPassword(password, saltBase64, iterations=150000){
  const saltBuf = base64ToBuf(saltBase64);
  const baseKey = await crypto.subtle.importKey(
    'raw',
    utf8.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    {name:'PBKDF2', salt: new Uint8Array(saltBuf), iterations: iterations, hash:'SHA-256'},
    baseKey,
    {name:'AES-GCM', length:256},
    true,
    ['encrypt','decrypt']
  );
  return key;
}

/* Encrypt text using AES-GCM */
async function encryptWithKey(key, plainText){
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv: iv}, key, utf8.encode(plainText));
  return { ct: bufToBase64(ct), iv: bufToBase64(iv) };
}

/* Decrypt */
async function decryptWithKey(key, ctBase64, ivBase64){
  try{
    const ctBuf = base64ToBuf(ctBase64);
    const ivBuf = base64ToBuf(ivBase64);
    const plainBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv: new Uint8Array(ivBuf)}, key, ctBuf);
    return txtdec.decode(plainBuf);
  }catch(e){
    // bad key or tampered data
    return null;
  }
}

/* Export CryptoKey raw to base64 so we can persist it in sessionStorage for current session */
async function exportKeyRaw(key){
  const raw = await crypto.subtle.exportKey('raw', key);
  return bufToBase64(raw);
}
async function importKeyRaw(rawBase64){
  const rawBuf = base64ToBuf(rawBase64);
  return await crypto.subtle.importKey('raw', rawBuf, 'AES-GCM', true, ['encrypt','decrypt']);
}

/* localStorage helpers */
function loadUsers(){
  const raw = localStorage.getItem('pv_users');
  return raw ? JSON.parse(raw) : [];
}
function saveUsers(users){
  localStorage.setItem('pv_users', JSON.stringify(users));
}

/* generate a random salt base64 */
function genSaltBase64(){
  return bufToBase64(randBytes(16).buffer);
}

/* simple ID generator */
function idNow(){ return Date.now().toString(36) + Math.random().toString(36).substr(2,5); }

/* show simple toast/alert for demo */
function showAlert(msg){
  alert(msg);
}

/* ---------------------- Page logic helpers ---------------------- */

/* Create new user on signup */
async function handleSignup(e){
  e.preventDefault();
  const name = document.getElementById('signup_name').value.trim();
  const email = document.getElementById('signup_email').value.trim().toLowerCase();
  const pw = document.getElementById('signup_password').value;
  const confirm = document.getElementById('signup_confirm').value;

  if(!name || !email || !pw) return showAlert('Fill all fields');
  if(pw !== confirm) return showAlert('Passwords do not match');

  let users = loadUsers();
  if(users.find(u => u.email === email)) return showAlert('An account with this email already exists');

  // create salt, derive key, create auth token
  const salt = genSaltBase64();
  const iterations = 150000;
  const key = await deriveKeyFromPassword(pw, salt, iterations);

  // encrypt a small auth text to verify future logins
  const auth = await encryptWithKey(key, 'pv-auth-test');

  const newUser = {
    name, email, salt, iterations,
    auth, entries: []
  };
  users.push(newUser);
  saveUsers(users);

  // export key raw and store in sessionStorage (so user stays logged in for demo)
  const rawKey = await exportKeyRaw(key);
  sessionStorage.setItem('pv_key', rawKey);
  sessionStorage.setItem('pv_email', email);

  // redirect to home
  window.location.href = 'home.html';
}

/* Login flow - verify master password */
async function handleLogin(e){
  e.preventDefault();
  const email = document.getElementById('login_email').value.trim().toLowerCase();
  const pw = document.getElementById('login_password').value;
  if(!email || !pw) return showAlert('Enter email & password');

  let users = loadUsers();
  const user = users.find(u => u.email === email);
  if(!user) return showAlert('User not found. Sign up first.');

  // derive key using stored salt/iter and try to decrypt auth token
  const key = await deriveKeyFromPassword(pw, user.salt, user.iterations);
  const plain = await decryptWithKey(key, user.auth.ct, user.auth.iv);
  if(plain !== 'pv-auth-test') return showAlert('Invalid master password');

  // store raw key in sessionStorage for session use
  const rawKey = await exportKeyRaw(key);
  sessionStorage.setItem('pv_key', rawKey);
  sessionStorage.setItem('pv_email', email);

  window.location.href = 'home.html';
}

/* Ensure user is logged in (session) and import key */
async function requireAuthOrRedirect(){
  const email = sessionStorage.getItem('pv_email');
  const rawKey = sessionStorage.getItem('pv_key');
  if(!email || !rawKey){
    window.location.href = 'login.html';
    return null;
  }
  const key = await importKeyRaw(rawKey);
  return {email, key};
}

/* Add a new vault entry (encrypt password) */
async function handleAddEntry(e){
  e.preventDefault();
  const site = document.getElementById('site_name').value.trim();
  const username = document.getElementById('site_user').value.trim();
  const pass = document.getElementById('site_pass').value;

  if(!site || !username || !pass) return showAlert('Fill all fields');

  const auth = await requireAuthOrRedirect();
  if(!auth) return;

  const users = loadUsers();
  const user = users.find(u => u.email === auth.email);
  if(!user) return showAlert('User not found (storage issue)');

  // encrypt password with current key
  const enc = await encryptWithKey(auth.key, pass);

  const entry = { id: idNow(), site, user: username, pass: enc };
  user.entries.unshift(entry); // newest first
  saveUsers(users);

  // clear inputs
  document.getElementById('site_name').value = '';
  document.getElementById('site_user').value = '';
  document.getElementById('site_pass').value = '';

  await renderVaultTable(auth.key, user.entries);
}

/* Render table of entries (show masked password, reveal decrypt on demand) */
async function renderVaultTable(key, entries){
  const tbody = document.querySelector('#vaultTable tbody');
  if(!tbody) return;
  tbody.innerHTML = '';

  for(let ent of entries){
    const tr = document.createElement('tr');

    const tdSite = document.createElement('td'); tdSite.textContent = ent.site;
    const tdUser = document.createElement('td'); tdUser.textContent = ent.user;

    const tdPass = document.createElement('td');
    const passSpan = document.createElement('span'); passSpan.textContent = '••••••••';
    passSpan.id = 'p_' + ent.id;
    tdPass.appendChild(passSpan);

    const tdActions = document.createElement('td');

    // show/hide button
    const eye = document.createElement('button');
    eye.className = 'btn small';
    eye.innerHTML = '<i class="fas fa-eye"></i>';
    eye.title = 'Show password';
    eye.addEventListener('click', async ()=>{
      const cur = document.getElementById('p_' + ent.id);
      if(cur.dataset.revealed === '1'){
        cur.textContent = '••••••••';
        cur.dataset.revealed = '0';
        eye.innerHTML = '<i class="fas fa-eye"></i>';
        eye.title = 'Show password';
        return;
      }
      const plain = await decryptWithKey(key, ent.pass.ct, ent.pass.iv);
      if(plain === null) return showAlert('Unable to decrypt (session expired?)');
      cur.textContent = plain;
      cur.dataset.revealed = '1';
      eye.innerHTML = '<i class="fas fa-eye-slash"></i>';
      eye.title = 'Hide password';
    });

    // copy button
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn small';
    copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
    copyBtn.title = 'Copy password';
    copyBtn.addEventListener('click', async ()=>{
      const plain = await decryptWithKey(key, ent.pass.ct, ent.pass.iv);
      if(plain === null) return showAlert('Unable to decrypt (session expired?)');
      await navigator.clipboard.writeText(plain);
      showAlert('Password copied to clipboard');
    });

    // delete button
    const delBtn = document.createElement('button');
    delBtn.className = 'btn small danger';
    delBtn.innerHTML = '<i class="fas fa-trash"></i>';
    delBtn.title = 'Delete entry';
    delBtn.addEventListener('click', ()=>{
      if(!confirm('Delete this entry?')) return;
      let users = loadUsers();
      const u = users.find(x=>x.email === sessionStorage.getItem('pv_email'));
      if(!u) return;
      u.entries = u.entries.filter(x=>x.id !== ent.id);
      saveUsers(users);
      tr.remove();
    });

    tdActions.appendChild(eye);
    tdActions.appendChild(copyBtn);
    tdActions.appendChild(delBtn);

    tr.appendChild(tdSite);
    tr.appendChild(tdUser);
    tr.appendChild(tdPass);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  }
}

/* generate a decent random password (for demo) */
function generatePassword(length = 14){
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
  let out = '';
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  for(let i=0;i<length;i++){
    out += chars[arr[i] % chars.length];
  }
  return out;
}

/* Logout clears sessionStorage */
function logout(){
  sessionStorage.removeItem('pv_key');
  sessionStorage.removeItem('pv_email');
  window.location.href = 'login.html';
}

/* --- Profile: change master password (re-encrypt entries) --- */
async function handleChangeMaster(e){
  e.preventDefault();
  const oldP = document.getElementById('old_master').value;
  const newP = document.getElementById('new_master').value;
  const confirm = document.getElementById('new_confirm').value;
  if(!oldP || !newP) return showAlert('Fill password fields');
  if(newP !== confirm) return showAlert('New passwords do not match');

  // verify old with stored user auth
  const email = sessionStorage.getItem('pv_email');
  let users = loadUsers();
  const user = users.find(u => u.email === email);
  if(!user) return showAlert('No user - storage issue');

  // derive old key
  const oldKey = await deriveKeyFromPassword(oldP, user.salt, user.iterations);
  const ok = await decryptWithKey(oldKey, user.auth.ct, user.auth.iv);
  if(ok !== 'pv-auth-test') return showAlert('Current master password is incorrect');

  // generate new salt / key, re-encrypt all entries
  const newSalt = genSaltBase64();
  const iterations = 150000;
  const newKey = await deriveKeyFromPassword(newP, newSalt, iterations);

  // decrypt each entry with oldKey then re-encrypt with newKey
  for(let i=0;i<user.entries.length;i++){
    const ent = user.entries[i];
    const plain = await decryptWithKey(oldKey, ent.pass.ct, ent.pass.iv);
    const newEnc = await encryptWithKey(newKey, plain);
    ent.pass = newEnc;
  }

  // update user meta: salt, iterations, auth
  const newAuth = await encryptWithKey(newKey, 'pv-auth-test');
  user.salt = newSalt;
  user.iterations = iterations;
  user.auth = newAuth;

  saveUsers(users);

  // update session stored key
  const rawKey = await exportKeyRaw(newKey);
  sessionStorage.setItem('pv_key', rawKey);
  showAlert('Master password changed successfully');
  // clear inputs
  document.getElementById('old_master').value = '';
  document.getElementById('new_master').value = '';
  document.getElementById('new_confirm').value = '';
}

/* ---------------------- Initialize per page ---------------------- */

document.addEventListener('DOMContentLoaded', async ()=>{
  const page = document.body.dataset.page;

  if(page === 'signup'){
    const form = document.getElementById('signup-form');
    form.addEventListener('submit', handleSignup);
  }

  if(page === 'login'){
    const form = document.getElementById('login-form');
    form.addEventListener('submit', handleLogin);
  }

  if(page === 'home'){
    // require auth and import key
    const auth = await requireAuthOrRedirect();
    if(!auth) return;
    // import key object
    auth.key = await importKeyRaw(sessionStorage.getItem('pv_key'));

    // setup form events
    document.getElementById('entry-form').addEventListener('submit', handleAddEntry);
    document.getElementById('generateBtn').addEventListener('click', (ev)=>{
      ev.preventDefault();
      document.getElementById('site_pass').value = generatePassword(14);
    });
    document.getElementById('logoutBtn').addEventListener('click', logout);

    // load user's entries and render
    const users = loadUsers();
    const user = users.find(u => u.email === auth.email);
    if(user){
      await renderVaultTable(auth.key, user.entries);
    }
  }

  if(page === 'profile'){
    // require auth
    const auth = await requireAuthOrRedirect();
    if(!auth) return;
    auth.key = await importKeyRaw(sessionStorage.getItem('pv_key'));

    const users = loadUsers();
    const user = users.find(u => u.email === auth.email);
    if(!user) return;
    document.getElementById('profile_name').textContent = user.name;
    document.getElementById('profile_email').textContent = user.email;

    document.getElementById('change-pass-form').addEventListener('submit', handleChangeMaster);
    document.getElementById('logoutBtn2').addEventListener('click', logout);
  }

  if(page === 'about'){
    // no auth required; nothing special here
  }
});

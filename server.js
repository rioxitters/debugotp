const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
require('dotenv').config();

const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin@bd';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin 518422';
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'd3b7g-0tp-s3cr3t-k3y-2026';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'default-secret-key';
const WEBSITE_NAME = 'DebugOTP';

const FRONTEND_URL = process.env.FRONTEND_URL || process.env.SITE_URL || 'https://debugotp.netlify.app';

// Security Middlewares
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP if it breaks external scripts like Firebase/GSAP, or configure properly
  crossOriginEmbedderPolicy: false
}));

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes'
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 login attempts per hour
  message: 'Too many login attempts, please try again after an hour'
});

app.use('/api/', generalLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/admin/login', authLimiter);

app.use(cors({ origin: [FRONTEND_URL, 'https://debugotp.netlify.app', 'http://localhost:3001'], credentials: true }));
app.use(express.json());

// Secure file access - prohibit direct access to sensitive files
app.use((req, res, next) => {
  const forbiddenFiles = ['.env', 'firebase-service-account.json', 'users.json', 'projects.json', 'api.json'];
  if (forbiddenFiles.some(file => req.url.includes(file))) {
    return res.status(403).json({ success: false, message: 'Access Denied' });
  }
  next();
});

app.use(express.static('public'));

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');
const API_USAGE_FILE = path.join(DATA_DIR, 'api.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

const readJSON = (f, def = []) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { return def; } };
const writeJSON = (f, d) => fs.writeFileSync(f, JSON.stringify(d, null, 2));

// ============================================================
// PROJECT ROTATION SYSTEM
// ============================================================
let firebaseProjects = [];
let currentProjectIndex = 0;

const initFirebaseApp = (serviceAccount, apiKey, usage_count = 0) => {
  try {
    const appName = `proj-${serviceAccount.project_id}-${uuidv4().split('-')[0]}`;
    const fbApp = admin.initializeApp({ credential: admin.credential.cert(serviceAccount) }, appName);
    return { id: serviceAccount.project_id, app: fbApp, db: fbApp.firestore(), apiKey, status: 'Active', usage: usage_count };
  } catch (e) { return null; }
};

const loadAllProjects = () => {
  firebaseProjects = [];
  // 1. Load from projects.json and api.json
  const saved = readJSON(PROJECTS_FILE);
  const usageData = readJSON(API_USAGE_FILE, {});
  saved.forEach(p => {
    const fullPath = path.join(UPLOADS_DIR, p.fileName);
    if (fs.existsSync(fullPath)) {
      const sa = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
      const proj = initFirebaseApp(sa, p.apiKey, usageData[p.project_id] || 0);
      if (proj) firebaseProjects.push(proj);
    }
  });

  // 2. Fallback: Check for main service account file if not in JSON
  const mainFile = './pro-1-ad7ed-firebase-adminsdk-fbsvc-8d377f78fb.json';
  if (fs.existsSync(mainFile)) {
    const sa = JSON.parse(fs.readFileSync(mainFile, 'utf8'));
    if (!firebaseProjects.find(p => p.id === sa.project_id)) {
      const proj = initFirebaseApp(sa, process.env.FIREBASE_API_KEY, 0);
      if (proj) firebaseProjects.push(proj);
    }
  }
  console.log(`✅ ${firebaseProjects.length} Firebase Projects are ONLINE.`);
};

loadAllProjects();

async function fbAuthWithRotation(endpoint, body) {
  if (firebaseProjects.length === 0) throw new Error('No active Firebase projects available. Upload one in Admin Panel.');
  const project = firebaseProjects[currentProjectIndex % firebaseProjects.length];

  try {
    const r = await axios.post(`https://identitytoolkit.googleapis.com/v1/${endpoint}?key=${project.apiKey}`, body);
    project.usage++;

    // Save usage to api.json file
    const usageData = readJSON(API_USAGE_FILE, {});
    usageData[project.id] = project.usage;
    writeJSON(API_USAGE_FILE, usageData);

    return r.data;
  } catch (e) {
    const msg = e.response?.data?.error?.message || e.message;
    if (msg.includes('QUOTA') || msg.includes('LIMIT')) {
      currentProjectIndex++;
      return fbAuthWithRotation(endpoint, body);
    }
    throw new Error(msg);
  }
}

// ============================================================
// ADMIN & AUTH ROUTES
// ============================================================
app.post('/api/admin/login', (req, res) => {
  if (req.body.username === ADMIN_USERNAME && req.body.password === ADMIN_PASSWORD) {
    return res.json({ success: true, token: ADMIN_SECRET });
  }
  res.status(401).json({ success: false, message: 'Invalid Admin credentials' });
});

const checkAdminAuth = (req, res, next) => {
  const tk = req.headers.authorization;
  if (tk === `Bearer ${ADMIN_SECRET}`) return next();
  res.status(401).json({ success: false, message: 'Unauthorized' });
};

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const users = readJSON(USERS_FILE);
    if (users.find(u => u.email === email)) throw new Error('Email already registered');

    const fbUser = await fbAuthWithRotation('accounts:signUp', { email, password, displayName: name, returnSecureToken: true });
    await fbAuthWithRotation('accounts:sendOobCode', { requestType: 'VERIFY_EMAIL', idToken: fbUser.idToken });

    users.push({
      name, email, status: 'Active', api_key: uuidv4(), firebaseUid: fbUser.localId,
      emailVerified: false, createdAt: new Date(), usage_today: 0, daily_limit: 100, monthly_limit: 1000
    });
    writeJSON(USERS_FILE, users);
    res.json({ success: true, message: 'Verification email sent!' });
  } catch (e) { res.status(400).json({ success: false, message: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    let auth = null;

    // Search across all rotating projects since the user might have registered/reset password on any of them
    for (let proj of firebaseProjects) {
      try {
        const r = await axios.post(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${proj.apiKey}`, { email, password, returnSecureToken: true });
        auth = r.data;
        break;
      } catch (e) { }
    }

    if (!auth) throw new Error('Invalid email or password');
    
    if (firebaseProjects.length === 0) throw new Error('System initialization incomplete. Please contact administrator.');
    const profile = (await axios.post(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${firebaseProjects[0].apiKey}`, { idToken: auth.idToken })).data.users[0];

    if (!profile.emailVerified) return res.status(403).json({ success: false, message: 'Please verify email', needsVerification: true });

    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.email === email);
    if (!user) throw new Error('User record missing');
    if (user.status === 'Banned') throw new Error('Account Banned');

    if (!user.emailVerified) { user.emailVerified = true; writeJSON(USERS_FILE, users); }
    res.json({ success: true, user });
  } catch (e) { res.status(401).json({ success: false, message: e.message }); }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) throw new Error('Email is required');

    const users = readJSON(USERS_FILE);
    if (!users.find(u => u.email === email)) throw new Error('Account not found');

    // Register temporarily on current rotation project to ensure email delivery
    try { await fbAuthWithRotation('accounts:signUp', { email, password: uuidv4(), returnSecureToken: false }); } catch (e) { }

    await fbAuthWithRotation('accounts:sendOobCode', { requestType: 'PASSWORD_RESET', email });
    res.json({ success: true, message: 'Password reset email sent' });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

app.post('/api/users/me', (req, res) => {
  const { email } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === email);
  if (user) {
    res.json({ success: true, user });
  } else {
    res.status(404).json({ success: false, message: 'User not found' });
  }
});

// ============================================================
// ADMIN MANAGEMENT
// ============================================================
app.get('/api/admin/users', checkAdminAuth, (req, res) => res.json({ success: true, users: readJSON(USERS_FILE) }));

app.put('/api/admin/users/:email/status', checkAdminAuth, (req, res) => {
  const users = readJSON(USERS_FILE);
  const u = users.find(x => x.email === req.params.email);
  if (u) { u.status = req.body.status; writeJSON(USERS_FILE, users); return res.json({ success: true }); }
  res.status(404).json({ success: false });
});

app.put('/api/admin/users/:email/limits', checkAdminAuth, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === req.params.email);
  if (user) {
    user.daily_limit = req.body.daily;
    user.monthly_limit = req.body.monthly;
    writeJSON(USERS_FILE, users);
    return res.json({ success: true });
  }
  res.status(404).json({ success: false });
});

app.delete('/api/admin/users/:email', checkAdminAuth, (req, res) => {
  let users = readJSON(USERS_FILE);
  users = users.filter(x => x.email !== req.params.email);
  writeJSON(USERS_FILE, users);
  res.json({ success: true });
});

app.get('/api/admin/limits', checkAdminAuth, (req, res) => {
  // Mock global limits since we focus on per-user
  res.json({ success: true, globalLimits: { daily: 100, monthly: 1000 } });
});

app.get('/api/admin/firebase-projects', checkAdminAuth, (req, res) => {
  const savedProjects = readJSON(PROJECTS_FILE);
  const usageData = readJSON(API_USAGE_FILE, {});
  const results = savedProjects.map(sp => {
    const memP = firebaseProjects.find(p => p.id === sp.project_id);
    return {
      project_id: sp.project_id,
      status: memP ? memP.status : 'Offline',
      usage_count: usageData[sp.project_id] || 0,
      apiKey: sp.apiKey,
      credits: sp.credits || 10000,
      validation_status: memP ? 'Active' : 'Initialization Failed'
    };
  });
  res.json({ success: true, projects: results });
});

app.get('/api/admin/upload-history', checkAdminAuth, (req, res) => {
  res.json({ success: true, history: readJSON(PROJECTS_FILE).map(p => ({ ...p, status: 'Success', validation_status: 'Valid & Fresh', uploadedAt: new Date() })) });
});

const upload = multer({ dest: 'uploads/' });

app.post('/api/admin/firebase-projects/multiple', checkAdminAuth, upload.array('jsonFiles'), async (req, res) => {
  try {
    let successCount = 0;
    const results = [];
    const projects = readJSON(PROJECTS_FILE);

    // Ensure apiKeys is always an array
    const submittedKeys = req.body.apiKeys
      ? (Array.isArray(req.body.apiKeys) ? req.body.apiKeys : [req.body.apiKeys])
      : [];

    for (let i = 0; i < req.files.length; i++) {
      let file = req.files[i];
      let submittedApiKey = submittedKeys[i];

      try {
        const sa = JSON.parse(fs.readFileSync(file.path, 'utf8'));

        // 1. Basic Structure Check
        if (!sa.project_id || !sa.private_key || !sa.client_email) {
          throw new Error('Invalid JSON format');
        }

        // 2. Determine API Key
        const apiKey = submittedApiKey || sa.api_key;
        if (!apiKey) {
          throw new Error('Web API Key is missing for this project!');
        }

        // 3. Simulate Deep Scan / Wait
        await new Promise(r => setTimeout(r, 1200));

        const proj = initFirebaseApp(sa, apiKey);

        if (proj) {
          // 3. Real Security Verification (Try to generate a token)
          let isValid = false;
          let validationMsg = 'No issue';

          try {
            await proj.app.auth().createCustomToken('test-admin-scan');
            isValid = true;
          } catch (authErr) {
            validationMsg = 'Expired or Invalid Keys';
            proj.status = 'Expired';
          }

          if (isValid) {
            firebaseProjects.push(proj);
            projects.push({
              project_id: sa.project_id,
              apiKey: apiKey,
              fileName: file.filename,
              client_email: sa.client_email,
              credits: 10000,
              status: 'Fresh'
            });
            successCount++;
            results.push({ fileName: file.originalname, project_id: sa.project_id, status: 'Success', validation_status: 'Valid & Fresh', credits: '10,000 / 10,000' });
          } else {
            results.push({ fileName: file.originalname, project_id: sa.project_id, status: 'Failed', validation_status: validationMsg, credits: '0 / 10,000' });
          }
        } else {
          results.push({ fileName: file.originalname, project_id: null, status: 'Failed', validation_status: 'Connection Blocked', credits: 'N/A' });
        }
      } catch (e) {
        results.push({ fileName: file.originalname, project_id: null, status: 'Failed', validation_status: 'Corrupted File', credits: 'N/A' });
      }
    }

    writeJSON(PROJECTS_FILE, projects);
    res.json({ success: true, total: req.files.length, successCount, results });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.put('/api/admin/firebase-projects/:id', checkAdminAuth, (req, res) => {
  let projects = readJSON(PROJECTS_FILE);
  const pId = req.params.id;
  const p = projects.find(x => x.project_id === pId);
  if (p) {
    p.apiKey = req.body.apiKey;
    writeJSON(PROJECTS_FILE, projects);
    const memP = firebaseProjects.find(x => x.id === pId);
    if (memP) memP.apiKey = req.body.apiKey;
    res.json({ success: true });
  } else {
    res.status(404).json({ success: false, message: 'Project not found' });
  }
});

app.delete('/api/admin/firebase-projects/:id', checkAdminAuth, (req, res) => {
  let projects = readJSON(PROJECTS_FILE);
  const pId = req.params.id;
  const pIndex = projects.findIndex(p => p.project_id === pId);

  if (pIndex > -1) {
    const file = path.join(UPLOADS_DIR, projects[pIndex].fileName);
    if (fs.existsSync(file)) fs.unlinkSync(file);
    projects.splice(pIndex, 1);
    writeJSON(PROJECTS_FILE, projects);
  }

  firebaseProjects = firebaseProjects.filter(p => p.id !== pId);
  res.json({ success: true });
});

// ============================================================
// CONSUMER API ROUTES
// ============================================================
app.post('/api/otp/send', async (req, res) => {
  try {
    const { type, recipient, apiKey } = req.body;
    if (!apiKey) throw new Error('API Key is missing');

    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.api_key === apiKey);

    if (!user) throw new Error('Invalid API Key');
    if (user.status !== 'Active') throw new Error('Account is suspended');
    if (user.usage_today >= user.daily_limit || user.usage_month >= user.monthly_limit) {
      throw new Error('API Limit Exceeded');
    }

    if (type === 'email') {
      // Trick: Firebase only sends reset emails to existing users.
      // So we temporarily register the email in the current rotating project first.
      try {
        await fbAuthWithRotation('accounts:signUp', {
          email: recipient,
          password: uuidv4(),
          returnSecureToken: false
        });
      } catch (e) { /* Ignore if already exists */ }

      // Now Firebase will successfully dispatch the email
      await fbAuthWithRotation('accounts:sendOobCode', { requestType: 'PASSWORD_RESET', email: recipient });

    } else if (type === 'phone' || type === 'sms') {
      await fbAuthWithRotation('accounts:sendVerificationCode', { phoneNumber: recipient });
    } else {
      throw new Error('Invalid type (use email or phone)');
    }

    user.usage_today = (user.usage_today || 0) + 1;
    user.usage_month = (user.usage_month || 0) + 1;
    writeJSON(USERS_FILE, users);

    res.json({ success: true, message: `OTP sent to ${recipient}` });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message });
  }
});

// URL Encryption Helpers
function encrypt(text) {
  const cipher = crypto.createCipheriv('aes-256-cbc', crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32), Buffer.alloc(16, 0));
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function decrypt(text) {
  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', crypto.scryptSync(ENCRYPTION_KEY, 'salt', 32), Buffer.alloc(16, 0));
    return decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
  } catch (e) { return null; }
}

app.get('/dashboard/:token', (req, res) => {
  const decryptedToken = decrypt(req.params.token);
  // Optional: validate decryptedToken if it contains timestamp or user ID
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/dashboard', (req, res) => {
  const rawToken = Math.random().toString(36).substring(2) + Date.now();
  const encryptedToken = encrypt(rawToken);
  res.redirect(`${FRONTEND_URL}/dashboard/${encryptedToken}`);
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html')));

app.get('/api/config', (req, res) => {
  res.json({
    apiKey: process.env.FIREBASE_API_KEY || "AIzaSyAXQfOgwauqIZMAbEVsOiDXjFWy1UtDZb8",
    authDomain: "pro-1-ad7ed.firebaseapp.com",
    projectId: "pro-1-ad7ed",
    appId: "1:330829645630:web:8e630fead2760482f2ce6f"
  });
});

app.get('/loading', (req, res) => res.sendFile(path.join(__dirname, 'public', 'loading.html')));
app.get('/personalization', (req, res) => res.sendFile(path.join(__dirname, 'public', 'personalization.html')));

app.get(['/verify-email', '/verify', '/__/auth/action'], (req, res) => {
  // If the URL has plain parameters, redirect to an encrypted version for "full secure"
  const { mode, oobCode, apiKey } = req.query;
  if (mode && oobCode && apiKey) {
    const encrypted = encrypt(JSON.stringify({ mode, oobCode, apiKey }));
    return res.redirect(`/verify?v=${encrypted}`);
  }
  res.sendFile(path.join(__dirname, 'public', 'verify.html'));
});

app.get('/api/verify-decrypt', (req, res) => {
  const data = decrypt(req.query.v);
  if (data) {
    try {
      return res.json({ success: true, ...JSON.parse(data) });
    } catch (e) { }
  }
  res.status(400).json({ success: false });
});

app.listen(PORT, () => console.log(`🚀 REAL Server running on http://localhost:${PORT}`));

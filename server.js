const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

const ADMIN_USERNAME = 'admin@bd';
const ADMIN_PASSWORD = 'admin 518422';
const WEBSITE_NAME = 'DebugOTP';
let adminSession = null;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ============================================================
// FRONTEND ROUTES - Clean URLs (no .html)
// ============================================================

console.log('='.repeat(60));
console.log('Starting OTP Service Server...');
console.log('='.repeat(60));

let db = null;
let useFirebase = false;

try {
  console.log('Initializing Firebase Admin SDK with your service account...');
  const serviceAccount = require('./firebase-service-account.json');
  
  if (admin.apps.length === 0) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
  }
  
  if (admin.firestore) {
    db = admin.firestore();
    useFirebase = true;
    console.log('✅ Firebase Admin SDK initialized successfully!');
    console.log('✅ Project:', serviceAccount.project_id);
  }
} catch (e) {
  console.log('⚠️ Firebase initialization failed, using in-memory only');
  useFirebase = false;
}

const inMemoryUsers = {};
const inMemoryProjects = {};
let uploadHistory = [];
const globalLimits = {
  daily: 100,
  monthly: 1000
};
const userSpecificLimits = {};
const verificationCodes = {};

const upload = multer({ dest: 'uploads/' });

// ============================================================
// FRONTEND ROUTES (Clean URLs - no .html extension)
// ============================================================
// Home (Login/Signup)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/index', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Personalization
app.get('/personalization', (req, res) => res.sendFile(path.join(__dirname, 'public', 'personalization.html')));

// Loading Screen
app.get('/loading', (req, res) => res.sendFile(path.join(__dirname, 'public', 'loading.html')));

// User Dashboard
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

// Verify Page
app.get('/verify', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify.html')));

// Admin Login
app.get('/adminlogin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'adminlogin.html')));

// Admin Panel (Protected)
app.get('/admin', (req, res) => {
  if (adminSession) {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  } else {
    res.redirect('/adminlogin');
  }
});

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    adminSession = uuidv4();
    res.json({ success: true, token: adminSession });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  adminSession = null;
  res.json({ success: true });
});

const checkAdminAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader === `Bearer ${adminSession}` && adminSession) {
    next();
  } else {
    res.status(401).json({ success: false, message: 'Unauthorized' });
  }
};

app.post('/api/auth/send-verification', async (req, res) => {
  try {
    const { email, phone, purpose } = req.body;
    const key = email || phone;
    
    if (purpose === 'forgot') {
      let userExists = false;
      
      if (useFirebase && db) {
        try {
          const userDoc = await db.collection('Users').doc(key).get();
          userExists = userDoc.exists;
        } catch (e) {}
      }
      
      if (!userExists && !inMemoryUsers[key]) {
        return res.status(404).json({ success: false, message: 'User not found in ' + WEBSITE_NAME });
      }
    }
    
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    
    verificationCodes[key] = {
      code,
      purpose,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 10 * 60 * 1000)
    };
    
    console.log(`[${WEBSITE_NAME}] Verification code for ${key}: ${code}`);
    
    res.json({ 
      success: true, 
      message: `Verification code sent to ${key} from ${WEBSITE_NAME}`,
      sentTo: key
    });
  } catch (error) {
    console.error('Send verification error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/auth/verify-code', (req, res) => {
  try {
    const { email, phone, code } = req.body;
    const key = email || phone;
    const stored = verificationCodes[key];
    
    if (!stored) {
      return res.status(400).json({ success: false, message: 'No verification code sent from ' + WEBSITE_NAME });
    }
    
    if (new Date() > stored.expiresAt) {
      delete verificationCodes[key];
      return res.status(400).json({ success: false, message: 'Code expired' });
    }
    
    if (stored.code !== code) {
      return res.status(400).json({ success: false, message: 'Invalid code' });
    }
    
    delete verificationCodes[key];
    
    res.json({ success: true, message: 'Code verified successfully for ' + WEBSITE_NAME });
  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

const validateServiceAccount = async (credentials) => {
  try {
    if (!credentials) {
      return { valid: false, message: 'No credentials provided' };
    }
    
    if (!credentials.project_id || !credentials.private_key || !credentials.client_email) {
      return { valid: false, message: 'Invalid JSON - missing required fields' };
    }
    
    if (!credentials.private_key.includes('PRIVATE KEY')) {
      return { valid: false, message: 'Invalid private key format' };
    }
    
    if (!credentials.client_email.includes('iam.gserviceaccount.com')) {
      return { valid: false, message: 'Not a valid Firebase service account' };
    }
    
    return { valid: true, message: 'No issue' };
  } catch (error) {
    return { valid: false, message: 'Invalid file format' };
  }
};

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || name.length < 2) {
      return res.status(400).json({ success: false, message: 'Name must be at least 2 characters' });
    }
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email or phone is required' });
    }
    
    if (!password || password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    let emailExists = false;
    if (useFirebase && db) {
      try {
        const userDoc = await db.collection('Users').doc(email).get();
        emailExists = userDoc.exists;
      } catch (e) {}
    }
    
    if (emailExists || inMemoryUsers[email]) {
      return res.status(409).json({ success: false, message: 'This email or phone is already registered with ' + WEBSITE_NAME });
    }
    
    const apiKey = uuidv4();
    const userDoc = {
      name,
      email,
      password,
      status: 'Active',
      enabled_services: [],
      api_key: apiKey,
      createdAt: new Date(),
      usage_today: 0,
      usage_month: 0,
      last_used: null,
      daily_limit: globalLimits.daily,
      monthly_limit: globalLimits.monthly
    };
    
    if (useFirebase && db) {
      try {
        await db.collection('Users').doc(email).set(userDoc);
      } catch (e) {}
    }
    
    inMemoryUsers[email] = userDoc;
    userSpecificLimits[email] = {
      daily: userDoc.daily_limit,
      monthly: userDoc.monthly_limit
    };
    
    res.json({ success: true, user: userDoc, message: 'Account created successfully on ' + WEBSITE_NAME });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    let userData = null;
    
    if (useFirebase && db) {
      try {
        const userDoc = await db.collection('Users').doc(email).get();
        if (userDoc.exists) {
          userData = userDoc.data();
        }
      } catch (e) {}
    }
    
    if (!userData) {
      userData = inMemoryUsers[email];
    }
    
    if (!userData) {
      return res.status(404).json({ success: false, message: 'User not found in ' + WEBSITE_NAME });
    }
    
    if (userData.password !== password) {
      return res.status(401).json({ success: false, message: 'Invalid password' });
    }
    
    if (userData.status === 'Banned') {
      return res.status(403).json({ success: false, message: 'Account is banned from ' + WEBSITE_NAME });
    }
    
    res.json({ success: true, user: userData, message: 'Welcome back to ' + WEBSITE_NAME });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!password || password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    if (useFirebase && db) {
      try {
        await db.collection('Users').doc(email).update({ password });
      } catch (e) {}
    }
    
    if (inMemoryUsers[email]) {
      inMemoryUsers[email].password = password;
    }
    
    res.json({ success: true, message: 'Password reset successfully for ' + WEBSITE_NAME });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/users/:email/services', async (req, res) => {
  try {
    const { email } = req.params;
    const { enabled_services } = req.body;
    
    if (useFirebase && db) {
      try {
        await db.collection('Users').doc(email).update({ enabled_services });
      } catch (e) {}
    }
    
    if (inMemoryUsers[email]) {
      inMemoryUsers[email].enabled_services = enabled_services;
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Update services error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/admin/users', checkAdminAuth, async (req, res) => {
  try {
    let users = [];
    
    if (useFirebase && db) {
      try {
        const usersSnapshot = await db.collection('Users').get();
        users = usersSnapshot.docs.map(doc => doc.data());
      } catch (e) {}
    }
    
    if (users.length === 0) {
      users = Object.values(inMemoryUsers);
    }
    
    users = users.map(user => ({
      ...user,
      daily_limit: user.daily_limit || globalLimits.daily,
      monthly_limit: user.monthly_limit || globalLimits.monthly
    }));
    
    res.json({ success: true, users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put('/api/admin/users/:email/status', checkAdminAuth, async (req, res) => {
  try {
    const { email } = req.params;
    const { status } = req.body;
    
    if (useFirebase && db) {
      try {
        await db.collection('Users').doc(email).update({ status });
      } catch (e) {}
    }
    
    if (inMemoryUsers[email]) {
      inMemoryUsers[email].status = status;
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Update user status error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete('/api/admin/users/:email', checkAdminAuth, async (req, res) => {
  try {
    const { email } = req.params;
    
    if (useFirebase && db) {
      try {
        await db.collection('Users').doc(email).delete();
      } catch (e) {}
    }
    
    delete inMemoryUsers[email];
    delete userSpecificLimits[email];
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/admin/limits', checkAdminAuth, (req, res) => {
  res.json({ success: true, globalLimits, userSpecificLimits });
});

app.put('/api/admin/limits', checkAdminAuth, (req, res) => {
  const { daily, monthly } = req.body;
  if (daily !== undefined) globalLimits.daily = daily;
  if (monthly !== undefined) globalLimits.monthly = monthly;
  res.json({ success: true, globalLimits });
});

app.put('/api/admin/users/:email/limits', checkAdminAuth, async (req, res) => {
  try {
    const { email } = req.params;
    const { daily, monthly } = req.body;
    
    userSpecificLimits[email] = {
      daily: daily !== undefined ? daily : (userSpecificLimits[email]?.daily || globalLimits.daily),
      monthly: monthly !== undefined ? monthly : (userSpecificLimits[email]?.monthly || globalLimits.monthly)
    };
    
    if (useFirebase && db) {
      try {
        await db.collection('Users').doc(email).update({
          daily_limit: userSpecificLimits[email].daily,
          monthly_limit: userSpecificLimits[email].monthly
        });
      } catch (e) {}
    } else if (inMemoryUsers[email]) {
      inMemoryUsers[email].daily_limit = userSpecificLimits[email].daily;
      inMemoryUsers[email].monthly_limit = userSpecificLimits[email].monthly;
    }
    
    res.json({ success: true, userLimits: userSpecificLimits[email] });
  } catch (error) {
    console.error('Update user limits error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/firebase-projects/multiple', checkAdminAuth, upload.array('jsonFiles', 20), async (req, res) => {
  try {
    const results = [];
    
    for (const file of req.files) {
      try {
        const credentials = JSON.parse(fs.readFileSync(file.path, 'utf8'));
        
        const validation = await validateServiceAccount(credentials);
        
        const projectDoc = {
          id: uuidv4(),
          project_id: credentials.project_id,
          credentials,
          usage_count: 0,
          status: validation.valid ? 'Fresh' : 'Invalid',
          validation_status: validation.message,
          uploadedAt: new Date(),
          fileName: file.originalname,
        };
        
        if (useFirebase && db) {
          try {
            await db.collection('Firebase_Projects').doc(projectDoc.id).set(projectDoc);
          } catch (e) {}
        }
        
        inMemoryProjects[projectDoc.id] = projectDoc;
        
        const historyEntry = {
          id: projectDoc.id,
          project_id: projectDoc.project_id,
          fileName: file.originalname,
          status: validation.valid ? 'Success' : 'Failed',
          validation_status: validation.message,
          uploadedAt: new Date(),
        };
        
        uploadHistory.unshift(historyEntry);
        
        if (useFirebase && db) {
          try {
            await db.collection('Upload_History').doc(projectDoc.id).set(historyEntry);
          } catch (e) {}
        }
        
        results.push({
          project_id: credentials.project_id,
          fileName: file.originalname,
          status: validation.valid ? 'Success' : 'Failed',
          validation_status: validation.message,
        });
        
      } catch (parseError) {
        results.push({
          fileName: file.originalname,
          status: 'Failed',
          validation_status: 'Invalid JSON format'
        });
      } finally {
        try {
          fs.unlinkSync(file.path);
        } catch (e) {}
      }
    }
    
    res.json({ success: true, results, total: results.length, successCount: results.filter(r => r.status === 'Success').length });
  } catch (error) {
    console.error('Upload multiple files error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/admin/upload-history', checkAdminAuth, async (req, res) => {
  try {
    let history = [...uploadHistory];
    
    if (useFirebase && db && history.length === 0) {
      try {
        const historySnapshot = await db.collection('Upload_History').orderBy('uploadedAt', 'desc').get();
        history = historySnapshot.docs.map(doc => doc.data());
      } catch (e) {}
    }
    
    const { period } = req.query;
    const now = new Date();
    if (period === '7days') {
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      history = history.filter(h => new Date(h.uploadedAt) >= sevenDaysAgo);
    } else if (period === '30days') {
      const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      history = history.filter(h => new Date(h.uploadedAt) >= thirtyDaysAgo);
    }
    
    res.json({ success: true, history });
  } catch (error) {
    console.error('Get upload history error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/admin/firebase-projects', checkAdminAuth, upload.single('jsonFile'), async (req, res) => {
  try {
    const credentials = JSON.parse(fs.readFileSync(req.file.path, 'utf8'));
    
    const validation = await validateServiceAccount(credentials);
    
    const projectDoc = {
      id: uuidv4(),
      project_id: credentials.project_id,
      credentials,
      usage_count: 0,
      status: validation.valid ? 'Fresh' : 'Invalid',
      validation_status: validation.message,
      createdAt: new Date(),
    };
    
    if (useFirebase && db) {
      try {
        await db.collection('Firebase_Projects').doc(projectDoc.id).set(projectDoc);
      } catch (e) {}
    }
    
    inMemoryProjects[projectDoc.id] = projectDoc;
    
    const historyEntry = {
      id: projectDoc.id,
      project_id: projectDoc.project_id,
      fileName: req.file.originalname,
      status: validation.valid ? 'Success' : 'Failed',
      validation_status: validation.message,
      uploadedAt: new Date(),
    };
    
    uploadHistory.unshift(historyEntry);
    
    if (useFirebase && db) {
      try {
        await db.collection('Upload_History').doc(projectDoc.id).set(historyEntry);
      } catch (e) {}
    }
    
    fs.unlinkSync(req.file.path);
    res.json({ 
      success: true, 
      project: projectDoc,
      validation: validation
    });
  } catch (error) {
    console.error('Upload project error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/admin/firebase-projects', checkAdminAuth, async (req, res) => {
  try {
    let projects = [];
    
    if (useFirebase && db) {
      try {
        const projectsSnapshot = await db.collection('Firebase_Projects').get();
        projects = projectsSnapshot.docs.map(doc => doc.data());
      } catch (e) {}
    }
    
    if (projects.length === 0) {
      projects = Object.values(inMemoryProjects);
    }
    
    res.json({ success: true, projects });
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

const getFreshProject = async () => {
  if (useFirebase && db) {
    try {
      const projectsSnapshot = await db.collection('Firebase_Projects')
        .where('status', '==', 'Fresh')
        .where('validation_status', '==', 'No issue')
        .orderBy('usage_count', 'asc')
        .limit(1)
        .get();
      
      if (!projectsSnapshot.empty) {
        return projectsSnapshot.docs[0].data();
      }
    } catch (e) {}
  }
  
  const projects = Object.values(inMemoryProjects);
  const freshProjects = projects.filter(p => p.status === 'Fresh' && p.validation_status === 'No issue');
  if (freshProjects.length === 0) return null;
  return freshProjects.sort((a, b) => a.usage_count - b.usage_count)[0];
};

app.post('/api/otp/send', async (req, res) => {
  try {
    const { type, recipient, apiKey } = req.body;
    
    let user = null;
    if (useFirebase && db) {
      try {
        const usersSnapshot = await db.collection('Users').where('api_key', '==', apiKey).get();
        if (!usersSnapshot.empty) {
          user = usersSnapshot.docs[0].data();
        }
      } catch (e) {}
    }
    
    if (!user) {
      const users = Object.values(inMemoryUsers);
      user = users.find(u => u.api_key === apiKey);
    }
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid API key for ' + WEBSITE_NAME });
    }
    
    if (user.status === 'Banned') {
      return res.status(403).json({ success: false, message: 'Account is banned from ' + WEBSITE_NAME });
    }
    
    const userDailyLimit = userSpecificLimits[user.email]?.daily || user.daily_limit || globalLimits.daily;
    if (user.usage_today >= userDailyLimit) {
      return res.status(429).json({ success: false, message: 'Daily limit exceeded on ' + WEBSITE_NAME });
    }
    
    const project = await getFreshProject();
    if (!project) {
      return res.status(500).json({ success: false, message: 'No available Firebase projects for ' + WEBSITE_NAME });
    }
    
    const newUsageCount = project.usage_count + 1;
    let newStatus = project.status;
    if (newUsageCount >= 10000) {
      newStatus = 'Exhausted';
    }
    
    if (useFirebase && db) {
      try {
        await db.collection('Firebase_Projects').doc(project.id).update({
          usage_count: newUsageCount,
          status: newStatus,
        });
      } catch (e) {}
    }
    
    if (project.id && inMemoryProjects[project.id]) {
      inMemoryProjects[project.id].usage_count = newUsageCount;
      inMemoryProjects[project.id].status = newStatus;
    }
    
    const newUserUsageToday = (user.usage_today || 0) + 1;
    const newUserUsageMonth = (user.usage_month || 0) + 1;
    
    if (useFirebase && db) {
      try {
        await db.collection('Users').doc(user.email).update({
          usage_today: newUserUsageToday,
          usage_month: newUserUsageMonth,
          last_used: new Date()
        });
      } catch (e) {}
    } else if (inMemoryUsers[user.email]) {
      inMemoryUsers[user.email].usage_today = newUserUsageToday;
      inMemoryUsers[user.email].usage_month = newUserUsageMonth;
      inMemoryUsers[user.email].last_used = new Date();
    }
    
    res.json({ 
      success: true, 
      message: `OTP sent successfully to ${recipient} via ${WEBSITE_NAME}`,
      project_used: project.project_id,
      usage_count: newUsageCount
    });
  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

const server = app.listen(PORT, () => {
  console.log('='.repeat(60));
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`✅ Website Name: ${WEBSITE_NAME}`);
  console.log('='.repeat(60));
  console.log('🚀 Server is READY and STAYING ON!');
  console.log('='.repeat(60));
});

server.on('error', (err) => {
  console.error('❌ Server error:', err);
});

process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  console.log('✅ Server continuing to run...');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection:', reason);
  console.log('✅ Server continuing to run...');
});

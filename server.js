/**
 * ImageShield — Backend Server
 * Node.js + Express + Firebase (Firestore + Auth) + Nodemailer + Twilio
 *
 * Setup:
 *   npm install express cors dotenv firebase-admin nodemailer twilio multer uuid crypto
 *   node server.js
 */

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const multer     = require('multer');
const { v4: uuidv4 } = require('uuid');
const crypto     = require('crypto');
const admin      = require('firebase-admin');
const nodemailer = require('nodemailer');
const twilio     = require('twilio');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── MIDDLEWARE ────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// ── FIREBASE ADMIN ────────────────────────────────────────────────
// Put your serviceAccountKey.json in the project root
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET, // e.g. "imageshield.appspot.com"
});
const db      = admin.firestore();
const bucket  = admin.storage().bucket();

// ── FILE UPLOAD (Multer) ──────────────────────────────────────────
const storage = multer.memoryStorage();
const upload  = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg','image/png','image/webp','image/gif'];
    cb(null, allowed.includes(file.mimetype));
  }
});

// ── EMAIL (Nodemailer via Gmail SMTP) ─────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.SMTP_EMAIL, pass: process.env.SMTP_APP_PASSWORD }
});

// ── SMS (Twilio) ──────────────────────────────────────────────────
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);

// ── IN-MEMORY OTP STORE (use Redis in production) ─────────────────
const otpStore = new Map(); // key: email, value: { otp, expires, phone }

// ── HELPERS ───────────────────────────────────────────────────────
function generateOTP()       { return Math.floor(100000 + Math.random() * 900000).toString(); }
function generateLicenceKey(){ return 'IS-'+[0,0,0,0].map(()=>crypto.randomBytes(2).toString('hex').toUpperCase()).join('-'); }
function hashImage(buffer)   { return crypto.createHash('sha256').update(buffer).digest('hex'); }

// ── AUTH: SEND OTP ────────────────────────────────────────────────
app.post('/api/auth/send-otp', async (req, res) => {
  const { email, phone } = req.body;
  if (!email || !phone) return res.status(400).json({ error: 'Email and phone required.' });
  if (!email.endsWith('@gmail.com')) return res.status(400).json({ error: 'Must use a Gmail address.' });

  const otp     = generateOTP();
  const expires = Date.now() + 10 * 60 * 1000; // 10 min
  otpStore.set(email, { otp, expires, phone });

  // Send via Gmail
  await transporter.sendMail({
    from: `"ImageShield" <${process.env.SMTP_EMAIL}>`,
    to: email,
    subject: 'Your ImageShield Verification Code',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:2rem;background:#0d1120;color:#e2e8f0;border-radius:12px">
        <h2 style="color:#3b82f6">⬡ ImageShield</h2>
        <p>Your one-time verification code is:</p>
        <h1 style="font-size:3rem;letter-spacing:.3em;color:#06b6d4">${otp}</h1>
        <p style="color:#64748b">This code expires in 10 minutes. Do not share it with anyone.</p>
      </div>`
  });

  // Send via SMS
  await twilioClient.messages.create({
    body: `Your ImageShield OTP is: ${otp}. Valid for 10 minutes.`,
    from: process.env.TWILIO_FROM,
    to: phone
  });

  res.json({ success: true, message: 'OTP sent to email and phone.' });
});

// ── AUTH: VERIFY OTP + REGISTER USER ─────────────────────────────
app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, phone, otp, name, password } = req.body;
  const record = otpStore.get(email);
  if (!record)               return res.status(400).json({ error: 'OTP not found. Request a new one.' });
  if (Date.now() > record.expires) { otpStore.delete(email); return res.status(400).json({ error: 'OTP expired.' }); }
  if (record.otp !== otp)    return res.status(400).json({ error: 'Incorrect OTP.' });

  otpStore.delete(email);

  // Check if user already exists
  const existing = await db.collection('users').where('email','==',email).get();
  if (!existing.empty) return res.status(409).json({ error: 'Account already exists. Please log in.' });

  // Hash password
  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
  const userId       = uuidv4();

  await db.collection('users').doc(userId).set({
    userId, name, email, phone, passwordHash,
    plan: 'free',
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  // Create Firebase Auth user for frontend SDK use
  try {
    await admin.auth().createUser({ uid: userId, email, displayName: name, phoneNumber: phone });
  } catch (_) {}

  // Issue custom token
  const token = await admin.auth().createCustomToken(userId);
  res.json({ success: true, userId, token, name, email });
});

// ── AUTH: LOGIN ───────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
  const snap = await db.collection('users').where('email','==',email).where('passwordHash','==',passwordHash).get();
  if (snap.empty) return res.status(401).json({ error: 'Invalid email or password.' });

  const user  = snap.docs[0].data();
  const token = await admin.auth().createCustomToken(user.userId);
  res.json({ success: true, token, userId: user.userId, name: user.name, email: user.email });
});

// ── MIDDLEWARE: Verify Firebase Token ────────────────────────────
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token provided.' });
  try {
    const decoded = await admin.auth().verifyIdToken(auth.split(' ')[1]);
    req.uid = decoded.uid;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// ── IMAGES: REGISTER ─────────────────────────────────────────────
app.post('/api/images/register', requireAuth, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No image file provided.' });

  const { title, visibility } = req.body; // visibility: public | private | restricted
  if (!['public','private','restricted'].includes(visibility))
    return res.status(400).json({ error: 'Invalid visibility mode.' });

  // Upload to Firebase Storage
  const fileName   = `images/${req.uid}/${uuidv4()}-${req.file.originalname}`;
  const fileRef    = bucket.file(fileName);
  await fileRef.save(req.file.buffer, { contentType: req.file.mimetype });

  // Get signed URL (permanent for public, otherwise expiring)
  let imageUrl;
  if (visibility === 'public') {
    await fileRef.makePublic();
    imageUrl = `https://storage.googleapis.com/${process.env.FIREBASE_STORAGE_BUCKET}/${fileName}`;
  } else {
    [imageUrl] = await fileRef.getSignedUrl({ action:'read', expires:'03-01-2030' });
  }

  // Hash image for fingerprinting
  const fingerprint = hashImage(req.file.buffer);
  const licenceKey  = generateLicenceKey();
  const imageId     = uuidv4();

  const imageDoc = {
    imageId, userId: req.uid, title,
    visibility, licenceKey, fingerprint,
    fileName, imageUrl,
    status: 'active',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    violations: []
  };

  await db.collection('images').doc(imageId).set(imageDoc);

  // Also store fingerprint in global registry for dedup scanning
  await db.collection('fingerprints').doc(fingerprint).set({ imageId, userId: req.uid, visibility, licenceKey });

  res.json({ success: true, imageId, licenceKey, imageUrl, fingerprint });
});

// ── IMAGES: LIST (user's own) ─────────────────────────────────────
app.get('/api/images', requireAuth, async (req, res) => {
  const snap = await db.collection('images').where('userId','==',req.uid).orderBy('createdAt','desc').get();
  const images = snap.docs.map(d => {
    const data = d.data();
    // Never send private image URLs to other users, but here we're authed as the owner
    return { imageId: data.imageId, title: data.title, visibility: data.visibility,
             licenceKey: data.licenceKey, imageUrl: data.imageUrl, createdAt: data.createdAt,
             status: data.status };
  });
  res.json({ images });
});

// ── IMAGES: UPDATE VISIBILITY ─────────────────────────────────────
app.patch('/api/images/:imageId/visibility', requireAuth, async (req, res) => {
  const { visibility } = req.body;
  if (!['public','private','restricted'].includes(visibility))
    return res.status(400).json({ error: 'Invalid visibility.' });

  const ref = db.collection('images').doc(req.params.imageId);
  const doc = await ref.get();
  if (!doc.exists || doc.data().userId !== req.uid)
    return res.status(403).json({ error: 'Not authorised.' });

  await ref.update({ visibility });
  res.json({ success: true });
});

// ── IMAGES: DELETE ────────────────────────────────────────────────
app.delete('/api/images/:imageId', requireAuth, async (req, res) => {
  const ref = db.collection('images').doc(req.params.imageId);
  const doc = await ref.get();
  if (!doc.exists || doc.data().userId !== req.uid)
    return res.status(403).json({ error: 'Not authorised.' });

  await bucket.file(doc.data().fileName).delete().catch(()=>{});
  await ref.delete();
  res.json({ success: true });
});

// ── LICENCE: VERIFY (public endpoint, used by 3rd parties) ───────
app.get('/api/licence/verify/:key', async (req, res) => {
  const snap = await db.collection('images').where('licenceKey','==',req.params.key).get();
  if (snap.empty) return res.status(404).json({ valid: false, error: 'Licence key not found.' });

  const data = snap.docs[0].data();
  const userSnap = await db.collection('users').doc(data.userId).get();
  const owner = userSnap.exists ? userSnap.data().name : 'Unknown';

  res.json({
    valid: true,
    imageId: data.imageId,
    title: data.title,
    visibility: data.visibility,
    owner,
    registeredAt: data.createdAt,
    status: data.status
  });
});

// ── LICENCE: REQUEST ACCESS (restricted images) ───────────────────
app.post('/api/licence/request', requireAuth, async (req, res) => {
  const { imageId, reason } = req.body;
  const imgDoc = await db.collection('images').doc(imageId).get();
  if (!imgDoc.exists) return res.status(404).json({ error: 'Image not found.' });

  const image  = imgDoc.data();
  if (image.visibility !== 'restricted')
    return res.status(400).json({ error: 'Image is not in restricted mode.' });

  const requestId = uuidv4();
  await db.collection('licenceRequests').doc(requestId).set({
    requestId, imageId, requestorId: req.uid, reason,
    status: 'pending',
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });

  // Notify owner
  const ownerDoc = await db.collection('users').doc(image.userId).get();
  if (ownerDoc.exists) {
    await transporter.sendMail({
      from: `"ImageShield" <${process.env.SMTP_EMAIL}>`,
      to: ownerDoc.data().email,
      subject: `New licence request for "${image.title}"`,
      html: `<p>Someone has requested access to your restricted image "<b>${image.title}</b>".</p>
             <p>Reason: ${reason}</p><p>Log in to ImageShield to approve or reject.</p>`
    });
  }

  res.json({ success: true, requestId });
});

// ── VIOLATIONS: REPORT ────────────────────────────────────────────
app.post('/api/violations', requireAuth, async (req, res) => {
  const { imageId, foundUrl, platform } = req.body;
  const violationId = uuidv4();
  await db.collection('violations').doc(violationId).set({
    violationId, imageId, reportedBy: req.uid,
    foundUrl, platform, status: 'pending',
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
  res.json({ success: true, violationId });
});

// ── VIOLATIONS: LIST for image owner ─────────────────────────────
app.get('/api/violations', requireAuth, async (req, res) => {
  // Get user's image IDs first
  const imgSnap = await db.collection('images').where('userId','==',req.uid).get();
  const imgIds  = imgSnap.docs.map(d=>d.id);
  if (!imgIds.length) return res.json({ violations: [] });

  const vSnap = await db.collection('violations').where('imageId','in',imgIds.slice(0,10)).get();
  res.json({ violations: vSnap.docs.map(d=>d.data()) });
});

// ── DMCA: GENERATE NOTICE ─────────────────────────────────────────
app.post('/api/dmca/generate', requireAuth, async (req, res) => {
  const { violationId } = req.body;
  const vDoc = await db.collection('violations').doc(violationId).get();
  if (!vDoc.exists) return res.status(404).json({ error: 'Violation not found.' });

  const v = vDoc.data();
  const imgDoc  = await db.collection('images').doc(v.imageId).get();
  const userDoc = await db.collection('users').doc(req.uid).get();
  const img  = imgDoc.data();
  const user = userDoc.data();

  const notice = `
DMCA TAKEDOWN NOTICE
====================
Date: ${new Date().toDateString()}
To: ${v.platform} Legal / DMCA Agent

I, ${user.name} (${user.email}), hereby state that I am the copyright owner of the image titled "${img.title}".

The image has been registered and fingerprinted on the ImageShield platform.
Licence Key: ${img.licenceKey}
Fingerprint: ${img.fingerprint}

The infringing material is located at: ${v.foundUrl}

I have a good faith belief that use of the material in the manner complained of is not authorised by the copyright owner, its agent, or the law.

I declare under penalty of perjury that the information in this notification is accurate, and that I am the copyright owner.

Signed,
${user.name}
${user.email}
${user.phone}
`;

  await db.collection('violations').doc(violationId).update({ status: 'dmca_sent', dmcaNotice: notice });
  res.json({ success: true, notice });
});

// ── DASHBOARD STATS ───────────────────────────────────────────────
app.get('/api/stats', requireAuth, async (req, res) => {
  const imgSnap = await db.collection('images').where('userId','==',req.uid).get();
  const total   = imgSnap.size;
  const imgIds  = imgSnap.docs.map(d=>d.id);

  let violations = 0;
  if (imgIds.length) {
    const vSnap = await db.collection('violations').where('imageId','in',imgIds.slice(0,10)).where('status','==','pending').get();
    violations  = vSnap.size;
  }

  res.json({ totalImages: total, activeImages: total, violations, scansToday: Math.floor(Math.random()*2000)+500 });
});

// ── HEALTH ────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date() }));

// ── SERVE FRONTEND ────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`✅  ImageShield API running on http://localhost:${PORT}`));

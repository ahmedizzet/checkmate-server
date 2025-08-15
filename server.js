// server.js
// A simplified Express server to send FCM notifications.
// It uses modern Firebase Admin SDK methods and is easier to troubleshoot.

const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
app.use(cors({ origin: true }));
app.use(bodyParser.json({ limit: '256kb' }));

// Load serviceAccount.json (make sure file exists in the project root)
const serviceAccountPath = path.join(__dirname, 'serviceAccount.json');
let serviceAccount;
try {
  serviceAccount = require(serviceAccountPath);
} catch (err) {
  console.error('Could not load serviceAccount.json. Make sure the file exists in the project root.', err);
  process.exit(1);
}

// Initialize Firebase Admin SDK
try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log('Firebase Admin initialized.');
} catch (err) {
  console.error('Failed to initialize Firebase Admin SDK:', err);
  process.exit(1);
}

const db = admin.firestore();
const messaging = admin.messaging();

// Middleware to verify Firebase ID token
async function verifyFirebaseIdToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: missing Bearer token' });
  }
  const idToken = authHeader.split('Bearer ')[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('verifyIdToken error:', err);
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }
}

// Main endpoint to send notifications
app.post('/notify/task', verifyFirebaseIdToken, async (req, res) => {
  try {
    const callerUid = req.user.uid;
    const { groupId, taskId, title, body } = req.body || {};
    if (!groupId) return res.status(400).json({ error: 'Missing groupId' });

    // Fetch group data
    const groupSnap = await db.collection('groups').doc(groupId).get();
    if (!groupSnap.exists) {
      return res.status(404).json({ error: 'Group not found' });
    }
    const groupData = groupSnap.data() || {};
    const members = Array.isArray(groupData.members) ? groupData.members : [];
    const groupName = groupData.name || 'Group';

    // Verify the caller is a member
    if (!members.includes(callerUid)) {
      return res.status(403).json({ error: 'Forbidden: caller is not a member of the group' });
    }

    // Get the FCM tokens of all other members
    const memberUids = members.filter(uid => uid !== callerUid);
    const userDocPromises = memberUids.map(uid => db.collection('users').doc(uid).get());
    const userDocs = await Promise.all(userDocPromises);

    const tokens = [];
    for (const doc of userDocs) {
      if (!doc.exists) continue;
      const data = doc.data() || {};
      const fcmToken = data.fcmToken;
      if (fcmToken && typeof fcmToken === 'string' && fcmToken.trim().length > 0) {
        tokens.push(fcmToken);
      }
    }

    if (tokens.length === 0) {
      return res.json({ success: true, message: 'No tokens to notify', notified: 0 });
    }
    
    // Construct the notification message
    const notificationTitle = title || `New Task in ${groupName}`;
    const notificationBody = body || 'A new task was added';
    const dataPayload = {
      click_action: 'FLUTTER_NOTIFICATION_CLICK',
      groupId: String(groupId),
      ...(taskId ? { taskId: String(taskId) } : {}),
      sentBy: callerUid
    };

    const multicastMessage = {
      tokens: tokens,
      notification: { title: notificationTitle, body: notificationBody },
      data: dataPayload,
      android: { priority: 'high', notification: { sound: 'default' } },
      apns: { payload: { aps: { sound: 'default' } } }
    };
    
    // Send the notifications
    const resp = await messaging.sendEachForMulticast(multicastMessage);

    return res.json({
      success: true,
      message: `Notifications sent successfully: ${resp.successCount}`,
      notified: resp.successCount,
      failed: resp.failureCount,
    });

  } catch (err) {
    console.error('Unhandled error in /notify/task:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => res.send('OK'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Notifier server running on port ${PORT}`));

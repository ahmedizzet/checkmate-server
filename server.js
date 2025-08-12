// server.js
// Express notifier that verifies caller ID token and sends FCM notifications to group members.
// Uses firebase-admin.sendEachForMulticast when available, otherwise falls back to sendMulticast or sendToDevice.

const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
app.use(cors({ origin: true }));
app.use(bodyParser.json({ limit: '256kb' }));

// Load serviceAccount.json (make sure file exists)
const serviceAccountPath = path.join(__dirname, 'serviceAccount.json');
let serviceAccount;
try {
  serviceAccount = require(serviceAccountPath);
} catch (err) {
  console.error('Could not load serviceAccount.json. Make sure the file exists in the project root.', err);
  process.exit(1);
}

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
const messaging = admin.messaging(); // central messaging API

// Middleware: verify Authorization: Bearer <idToken>
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

function chunkArray(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

app.post('/notify/task', verifyFirebaseIdToken, async (req, res) => {
  try {
    const callerUid = req.user.uid;
    const { groupId, taskId, title, body } = req.body || {};
    if (!groupId) return res.status(400).json({ error: 'Missing groupId' });

    const groupSnap = await db.collection('groups').doc(groupId).get();
    if (!groupSnap.exists) return res.status(404).json({ error: 'Group not found' });
    const groupData = groupSnap.data() || {};
    const members = Array.isArray(groupData.members) ? groupData.members : [];
    const groupName = groupData.name || 'Group';

    if (!members.includes(callerUid)) {
      return res.status(403).json({ error: 'Forbidden: caller is not a member of the group' });
    }

    const memberUids = members.filter(uid => uid !== callerUid);
    if (memberUids.length === 0) {
      return res.json({ success: true, message: 'No other members to notify', notified: 0 });
    }

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

    if (tokens.length === 0) return res.json({ success: true, message: 'No tokens to notify', notified: 0 });

    const CHUNK_SIZE = 500;
    const tokenChunks = chunkArray(tokens, CHUNK_SIZE);

    const notificationTitle = title || `New Task in ${groupName}`;
    const notificationBody = body || (taskId ? `Task created (${taskId})` : 'A new task was added');

    const dataPayload = {
      click_action: 'FLUTTER_NOTIFICATION_CLICK',
      groupId: String(groupId),
      ...(taskId ? { taskId: String(taskId) } : {}),
      sentBy: callerUid
    };

    let totalSuccess = 0;
    let totalFailure = 0;
    const invalidTokensToRemove = new Set();

    for (const chunk of tokenChunks) {
      // Prefer sendEachForMulticast (newer admin SDK)
      if (typeof messaging.sendEachForMulticast === 'function') {
        const multicastMessage = {
          tokens: chunk,
          notification: { title: notificationTitle, body: notificationBody },
          data: dataPayload,
          android: { priority: 'high', notification: { sound: 'default' } },
          apns: { payload: { aps: { sound: 'default' } } }
        };

        let resp;
        try {
          resp = await messaging.sendEachForMulticast(multicastMessage);
        } catch (err) {
          console.error('Error calling sendEachForMulticast for chunk:', err);
          totalFailure += chunk.length;
          continue;
        }

        // resp.responses is an array of SendResponse-like objects
        const responses = Array.isArray(resp.responses) ? resp.responses : [];
        let successCount = 0;
        let failureCount = 0;
        responses.forEach((r, idx) => {
          if (r && r.success) {
            successCount++;
          } else {
            failureCount++;
            const token = chunk[idx];
            const err = r && r.error;
            const code = err && (err.code || (err.errorInfo && err.errorInfo.code));
            if (code === 'messaging/registration-token-not-registered' ||
                code === 'messaging/invalid-registration-token') {
              invalidTokensToRemove.add(token);
            } else {
              console.warn('sendEachForMulticast error for token:', token, code || err);
            }
          }
        });

        totalSuccess += successCount;
        totalFailure += failureCount;
      }
      // Fallback to sendMulticast if available (older API)
      else if (typeof messaging.sendMulticast === 'function') {
        const multicastMessage = {
          tokens: chunk,
          notification: { title: notificationTitle, body: notificationBody },
          data: dataPayload,
          android: { priority: 'high', notification: { sound: 'default' } },
          apns: { payload: { aps: { sound: 'default' } } }
        };

        let resp;
        try {
          resp = await messaging.sendMulticast(multicastMessage);
        } catch (err) {
          console.error('Error calling sendMulticast for chunk:', err);
          totalFailure += chunk.length;
          continue;
        }

        const successCount = resp.successCount || 0;
        const failureCount = resp.failureCount || 0;
        totalSuccess += successCount;
        totalFailure += failureCount;

        (resp.responses || []).forEach((r, idx) => {
          if (!r.success) {
            const token = chunk[idx];
            const err = r.error;
            const code = err && (err.code || (err.errorInfo && err.errorInfo.code));
            if (code === 'messaging/registration-token-not-registered' ||
                code === 'messaging/invalid-registration-token') {
              invalidTokensToRemove.add(token);
            } else {
              console.warn('sendMulticast error for token:', token, code || err);
            }
          }
        });
      }
      // Final fallback: sendToDevice (very old SDKs)
      else {
        const payload = {
          notification: { title: notificationTitle, body: notificationBody },
          data: dataPayload
        };
        let resp;
        try {
          resp = await messaging.sendToDevice(chunk, payload, { priority: 'high' });
        } catch (err) {
          console.error('Error using sendToDevice for chunk:', err);
          totalFailure += chunk.length;
          continue;
        }

        const results = resp.results || [];
        for (let i = 0; i < results.length; i++) {
          const r = results[i];
          const token = chunk[i];
          if (r && r.error) {
            totalFailure++;
            const code = r.error.code || (r.error.errorInfo && r.error.errorInfo.code);
            if (code === 'messaging/registration-token-not-registered' ||
                code === 'messaging/invalid-registration-token') {
              invalidTokensToRemove.add(token);
            } else {
              console.warn('sendToDevice error for token:', token, code || r.error);
            }
          } else {
            totalSuccess++;
          }
        }
      }
    } // end token chunk loop

    // Cleanup invalid tokens in Firestore
    if (invalidTokensToRemove.size > 0) {
      const invalidTokens = Array.from(invalidTokensToRemove);
      console.log('Invalid tokens to remove count:', invalidTokens.length);
      for (const token of invalidTokens) {
        try {
          const q = await db.collection('users').where('fcmToken', '==', token).get();
          for (const uDoc of q.docs) {
            try {
              await uDoc.ref.update({ fcmToken: admin.firestore.FieldValue.delete() });
              console.log(`Removed invalid token from user ${uDoc.id}`);
            } catch (e) {
              console.error(`Failed to remove invalid token for user ${uDoc.id}:`, e);
            }
          }
        } catch (e) {
          console.error('Error querying users for invalid token cleanup:', e);
        }
      }
    }

    return res.json({ success: true, notified: totalSuccess, failed: totalFailure });
  } catch (err) {
    console.error('Unhandled error in /notify/task:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/health', (req, res) => res.send('OK'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Notifier server running on port ${PORT}`));
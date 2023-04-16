const admin = require('firebase-admin');
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const serviceAccount = require('./ServiceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

//const hostname = '192.168.1.71';
const port = 8000;

function generateSecretKey(length) {
  let result = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

const secretKey = generateSecretKey(32);


app.get('/secret-key', (req, res) => {
  res.send(secretKey);
});

app.post('/deleteUser', async (req, res) => {
  const idToken = req.body.idToken;

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;
    const userRef = db.collection('users').doc(uid);
    const doc = await userRef.get();
  

    if (!doc.exists) {
      res.send('no user');
    } else {
      const role = doc.data().role;

      if (role == "admin") {
        const userID = req.body.uid;
        console.log(userID);

        try {
          await admin.auth().deleteUser(userID);
          await db.collection('users').doc(userID).delete();
          res.send('User deleted successfully.');
        } catch (error) {
          console.error("Error deleting user: ", error);
          res.send('Delete failed.');
        }
      } else {
        res.send('Not authorized.');
      }
    }

  } catch (error) {
    console.error("Error verifying ID token: ", error);
    res.send('Verification failed.');
  }

  jwt.sign({
    secretKey: secretKey
  }, secretKey, {
    expiresIn: '1h'
  }, (err, token) => {
    if (err) {
      console.log(err);
      res.sendStatus(500);
    } else {
      res.status(200).json({
        token: token
      });
    }
  });
});


app.post('/createUser', async (req, res) => {
  const idToken = req.body.idToken;

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;
    const userRef = db.collection('users').doc(uid);
    const doc = await userRef.get();

    if (!doc.exists) {
      res.send('no user');
    } else {
      const role = doc.data().role;
      if (role === 'admin') {
        const newUser = {
          email: req.body.email,
          emailVerified: false,
          displayName: req.body.firstname + ' ' + req.body.lastname,
          disabled: false,
        };

        try {
          const userRecord = await admin.auth().createUser(newUser);

          console.log('Successfully created new user:', userRecord.uid);

          const userDoc = {
            uid: userRecord.uid,
            email: userRecord.email,
            firstname: req.body.firstname,
            lastname: req.body.lastname,
            role: 'admin',
            type: 'player',
            age: 22,
            created_at : Number(Date.now()),
            last_login : Number(Date.now()),
            profilePicture: "https://firebasestorage.googleapis.com/v0/b/freedom-of-athletics-d4d04.appspot.com/o/profpics%2FprofilePicture.png?alt=media&token=ec571e70-8af6-435f-bd57-49cec1cd6434",
          };

          const result = await db.collection('users').doc(userRecord.uid).set(userDoc);

          console.log('User document created with ID:', userRecord.uid);

          res.send('User created successfully');
        } catch (error) {
          console.log('Error creating new user:', error);
          res.status(500).send('Error creating user');
        }
      } else {
        res.status(403).send('Forbidden');
      }
    }
  } catch (error) {
    console.log('Error verifying ID token:', error);
    res.status(401).send('Unauthorized');
  }

  jwt.sign(
    {
      secretKey: secretKey,
    },
    secretKey,
    {
      expiresIn: '1h',
    },
    (err, token) => {
      if (err) {
        console.log(err);
        res.sendStatus(500);
      } else {
        res.status(200).json({
          token: token,
        });
      }
    }
  );
});



app.listen(8000, () => {
  console.log(`Server running at 8000`);
});

const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const dotenv = require('dotenv');
const { MongoClient, ObjectId } = require('mongodb');
const MongoStore = require('connect-mongo'); // Correctly import connect-mongo
const multer = require('multer');
const path = require('path');

dotenv.config(); // Load environment variables

const app = express();


// Global database variable
let db;

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static('public'));


// Connect to MongoDB
MongoClient.connect(process.env.MONGO_URI)
  .then(client => {
    console.log('MongoDB connected');
    db = client.db(); // Store the database connection
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
  });

// Configure session with MongoDB storage
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URI, // Use the correct syntax
  collectionName: 'sessions',
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: sessionStore, // Use sessionStore
  cookie: { secure: false, httpOnly: true }
}));

// Set up Express
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Home page
app.get('/', async (req, res) => {
  if (req.session.userId) {
    try {
      const user = await db.collection('users').findOne({ _id: new ObjectId(req.session.userId) });
      res.render('index', { username: req.session.username, profilePicture: user.profilePicture });
    } catch (err) {
      console.error('Error fetching user profile:', err);
      res.redirect('/login');
    }
  } else {
    res.redirect('/login');
  }
});


// Registration page
app.get('/register', (req, res) => {
  res.render('register', { error: null }); 
});

// Handle user registration
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  // Validate inputs
  if (!username || !email || !password) {
    return res.render('register', { error: 'All fields are required' });
  }

  if (password.length < 6) {
    return res.render('register', { error: 'Password must be at least 6 characters long' });
  }

  try {
    const existingUser = await db.collection('users').findOne({ email });
    if (existingUser) {
      return res.render('register', { error: 'Email is already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { username, email, password: hashedPassword };

    await db.collection('users').insertOne(newUser);
    res.redirect('/login');
  } catch (err) {
    console.error('Registration error:', err);
    res.render('register', { error: 'Error registering user' });
  }
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null }); 
});

// Handle user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Validate email and password
  if (!email || !password) {
    return res.render('login', { error: 'Email and password are required' });
  }

  try {
    const user = await db.collection('users').findOne({ email });

    // If the user is not found
    if (!user) {
      return res.render('login', { error: 'Unregistered email' });
    }

    // If account is locked
    if (user.failedAttempts >= 5) {
      if (user.lockedUntil && new Date() < user.lockedUntil) {
        return res.render('login', { error: 'Account locked. Please try again later.' });
      }

      // Reset failed attempts after lock period
      await db.collection('users').updateOne(
        { _id: new ObjectId(user._id) },
        { $set: { failedAttempts: 0, lockedUntil: null } }
      );
    }

    // Check the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Increment failed attempts and lock account if necessary
      let updateData = { $inc: { failedAttempts: 1 } };

      if (user.failedAttempts >= 4) {
        // Lock account for 5 minutes after the 5th failed attempt
        updateData.$set = { lockedUntil: new Date(Date.now() + 5 * 60 * 1000) };
      }

      await db.collection('users').updateOne(
        { _id: new ObjectId(user._id) },
        updateData
      );

      return res.render('login', { error: 'Incorrect password' });
    }

    // Reset failed attempts on successful login
    await db.collection('users').updateOne(
      { _id: new ObjectId(user._id) },
      { $set: { failedAttempts: 0, lockedUntil: null } }
    );

    // Save session
    req.session.userId = user._id;
    req.session.username = user.username;
    res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    res.render('login', { error: 'Error logging in' });
  }
});

// Logout user
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads');
    console.log('Saving file to:', uploadPath); 
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    console.log('Saving file as:', file.originalname);
    cb(null, file.originalname);
  }
});


const upload = multer({ storage });

app.get('/edit-profile', async (req, res) => {
  if (req.session.userId) {
    const userId = req.session.userId;

    try {
      const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
      res.render('edit-profile', { 
        username: user.username, 
        email: user.email,  // Pass email to the view
        profilePicture: user.profilePicture || '',  // Pass profile picture if available
        error: null
      });
    } catch (err) {
      console.error('Error fetching user data:', err);
      res.status(500).send('Error fetching user data');
    }
  } else {
    res.redirect('/login');
  }
});


app.post('/edit-profile', upload.single('profilePicture'), async (req, res) => {
  const { username, email, currentPassword, newPassword } = req.body;
  const userId = req.session.userId;

  try {
    const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });

    // Check if current password matches the one stored in the database
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isCurrentPasswordValid) {
      return res.render('edit-profile', { 
        error: 'Incorrect password', 
        username: user.username, 
        email: user.email, 
        profilePicture: req.file ? '/uploads/' + req.file.filename : user.profilePicture 
      });
    }

    const profilePicture = req.file ? '/uploads/' + req.file.filename : user.profilePicture;

    // Prepare the update object
    const updateData = { 
      username: username, 
      email: email,
      profilePicture: req.file ? '/uploads/' + req.file.filename : '' ,
      error: null
    };

    // If the user wants to change the password
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateData.password = hashedPassword;
    }

    await db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: updateData }
    );

    req.session.username = username;
    res.redirect('/');
  } catch (err) {
    console.error('Error updating profile:', err);
    res.status(500).send('Error updating profile');
  }
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`http://localhost:${port}`); // Prints a link to the local site
});
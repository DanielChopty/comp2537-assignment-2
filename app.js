// Load environment variables from the .env file
require('dotenv').config();

// Import necessary dependencies
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { database } = require('./databaseConnection');

const saltRounds = 12;

// Load MongoDB and session config from environment variables
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_database_sessions = process.env.MONGODB_DATABASE_SESSIONS;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const app = express();
const port = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; // 1 hour

// View engine and middleware
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

// Session config
const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database_sessions}?retryWrites=true&w=majority`,
  collectionName: 'sessions',
  crypto: { secret: mongodb_session_secret },
});

app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}));

// Home route
app.get('/', (req, res) => {
  const user = req.session.authenticated ? {
    name: req.session.username,
    email: req.session.email,
    role: req.session.role
  } : null;

  res.render('index', { user });
});

// Signup form
app.get('/signup', (req, res) => {
  res.render('signup', { errorMessage: null });
});

// Signup handler
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error) {
    return res.render('signup', { errorMessage: validationResult.error.details[0].message });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  const userCollection = database.db(mongodb_database).collection('users');

  const existingUser = await userCollection.findOne({ email });
  if (existingUser) {
    return res.render('signup', { errorMessage: 'User with that email already exists!' });
  }

  const role = (email === 'admin@example.com') ? 'admin' : 'user';

  await userCollection.insertOne({ name, email, password: hashedPassword, role });

  req.session.authenticated = true;
  req.session.username = name;
  req.session.email = email;
  req.session.role = role;
  req.session.cookie.maxAge = expireTime;

  res.redirect('/members');
});

// Login form
app.get('/login', (req, res) => {
  res.render('login', { errorMessage: null });
});

// Login handler
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error) {
    return res.render('login', { errorMessage: validationResult.error.details[0].message });
  }

  const userCollection = database.db(mongodb_database).collection('users');
  const user = await userCollection.findOne({ email });

  if (!user) {
    return res.render('login', { errorMessage: 'User not found' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.render('login', { errorMessage: 'Incorrect password' });
  }

  req.session.authenticated = true;
  req.session.username = user.name;
  req.session.email = user.email;
  req.session.role = user.role;
  req.session.cookie.maxAge = expireTime;

  res.redirect('/members');
});

// Members page
app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/');
  }

  const user = {
    name: req.session.username,
    email: req.session.email,
    role: req.session.role
  };

  if (user.role === 'admin') {
    return res.render('admin', { user });
  } else {
    return res.render('user', { user });
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 404
app.use((req, res) => {
  res.status(404).render('404');
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

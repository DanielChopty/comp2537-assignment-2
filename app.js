require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { ObjectId } = require('mongodb');
const { database } = require('./databaseConnection');

const saltRounds = 12;
const app = express();
const port = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_database_sessions = process.env.MONGODB_DATABASE_SESSIONS;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// Middleware setup
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

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
  res.render('index', {
    authenticated: req.session.authenticated,
    username: req.session.username,
    role: req.session.role || 'user'
  });
});

// Signup
app.get('/signup', (req, res) => {
  res.render('signup', { errorMessage: null });
});

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const schema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const validation = schema.validate({ name, email, password });
  if (validation.error) {
    return res.render('signup', { errorMessage: validation.error.details[0].message });
  }

  const userCollection = database.db(mongodb_database).collection('users');
  const existingUser = await userCollection.findOne({ email });
  if (existingUser) {
    return res.render('signup', { errorMessage: 'User already exists.' });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword, role: 'user' });

  req.session.authenticated = true;
  req.session.username = name;
  req.session.email = email;
  req.session.role = 'user';
  req.session.cookie.maxAge = expireTime;

  res.redirect('/user');
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { errorMessage: null });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validation = schema.validate({ email, password });
  if (validation.error) {
    return res.render('login', { errorMessage: validation.error.details[0].message });
  }

  const userCollection = database.db(mongodb_database).collection('users');
  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.render('login', { errorMessage: 'User not found' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.render('login', { errorMessage: 'Incorrect password' });
  }

  req.session.authenticated = true;
  req.session.username = user.name;
  req.session.email = user.email;
  req.session.role = user.role;
  req.session.cookie.maxAge = expireTime;

  if (user.role === 'admin') {
    res.redirect('/admin');
  } else {
    res.redirect('/user');
  }
});

// User view
app.get('/user', (req, res) => {
  if (!req.session.authenticated || req.session.role !== 'user') {
    return res.redirect('/');
  }
  res.render('user', {
    username: req.session.username,
    email: req.session.email
  });
});

// Admin dashboard
app.get('/admin', async (req, res) => {
  if (!req.session.authenticated || req.session.role !== 'admin') {
    return res.status(403).send('Access denied');
  }

  const userCollection = database.db(mongodb_database).collection('users');
  const users = await userCollection.find().toArray();

  res.render('admin', {
    username: req.session.username,
    email: req.session.email,
    users
  });
});

// Promote user
app.get('/promote/:id', async (req, res) => {
  if (!req.session.authenticated || req.session.role !== 'admin') {
    return res.status(403).send('Access denied');
  }

  const userCollection = database.db(mongodb_database).collection('users');
  await userCollection.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { role: 'admin' } }
  );

  res.redirect('/admin');
});

// Demote user
app.get('/demote/:id', async (req, res) => {
  if (!req.session.authenticated || req.session.role !== 'admin') {
    return res.status(403).send('Access denied');
  }

  const userCollection = database.db(mongodb_database).collection('users');
  const user = await userCollection.findOne({ _id: new ObjectId(req.params.id) });

  // Prevent self-demotion
  if (user.email === req.session.email) {
    return res.redirect('/admin');
  }

  await userCollection.updateOne(
    { _id: new ObjectId(req.params.id) },
    { $set: { role: 'user' } }
  );

  res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('404');
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

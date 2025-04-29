require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { database } = require('./databaseConnection');
const saltRounds = 12;

const app = express();
const port = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database_sessions = process.env.MONGODB_DATABASE_SESSIONS;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database_sessions}?retryWrites=true&w=majority`,
  collectionName: 'sessions',
  crypto: { secret: mongodb_session_secret }
});

app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}));

// Middleware to protect admin routes
function requireAdmin(req, res, next) {
  if (req.session.authenticated && req.session.isAdmin) {
    next();
  } else {
    res.status(403).render('403', { message: "Access denied" });
  }
}

// Home
app.get('/', (req, res) => {
  res.render('index', {
    authenticated: req.session.authenticated,
    username: req.session.username,
    isAdmin: req.session.isAdmin
  });
});

// Signup GET
app.get('/signup', (req, res) => {
  res.render('signup', { errorMessage: null });
});

// Signup POST
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
  const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');
  const existingUser = await userCollection.findOne({ email });

  if (existingUser) {
    return res.render('signup', { errorMessage: 'User with that email already exists!' });
  }

  await userCollection.insertOne({ name, email, password: hashedPassword, isAdmin: false });

  req.session.authenticated = true;
  req.session.username = name;
  req.session.isAdmin = false;
  req.session.cookie.maxAge = expireTime;

  res.redirect('/members');
});

// Login GET
app.get('/login', (req, res) => {
  res.render('login', { errorMessage: null });
});

// Login POST
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

  const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');
  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.render('login', { errorMessage: 'User not found' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (validPassword) {
    req.session.authenticated = true;
    req.session.username = user.name;
    req.session.isAdmin = user.isAdmin || false;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
  } else {
    res.render('login', { errorMessage: 'Incorrect password' });
  }
});

// Members
app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/');
  }

  const images = ['/img1.png', '/img2.png', '/img3.png'];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  res.render('members', {
    username: req.session.username,
    randomImage
  });
});

// Admin page (only for admins)
app.get('/admin', requireAdmin, (req, res) => {
  res.render('admin', {
    username: req.session.username
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 403 Forbidden
app.get('/403', (req, res) => {
  res.status(403).render('403', { message: "Access denied" });
});

// 404 Not Found
app.use((req, res) => {
  res.status(404).render('404');
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

require('dotenv').config();

// Import necessary dependencies
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { ObjectId } = require('mongodb');
const { database } = require('./databaseConnection');

const saltRounds = 12;

// Load environment variables
const {
  MONGODB_USER,
  MONGODB_PASSWORD,
  MONGODB_HOST,
  MONGODB_DATABASE_USERS,
  MONGODB_DATABASE_SESSIONS,
  MONGODB_SESSION_SECRET,
  NODE_SESSION_SECRET,
  PORT
} = process.env;

const app = express();
const port = PORT || 3000;
const expireTime = 60 * 60 * 1000; // 1 hour

// Set EJS as the templating engine
app.set('view engine', 'ejs');

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

// Session store configuration
const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${MONGODB_USER}:${MONGODB_PASSWORD}@${MONGODB_HOST}/${MONGODB_DATABASE_SESSIONS}?retryWrites=true&w=majority`,
  collectionName: 'sessions',
  crypto: { secret: MONGODB_SESSION_SECRET },
});

app.use(session({
  secret: NODE_SESSION_SECRET,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}));

// Middleware to make 'title' available in all templates
app.use((req, res, next) => {
  res.locals.title = 'My Web App';
  next();
});

// Routes

// Home page
app.get('/', (req, res) => {
  res.render('index', {
    title: 'Home',
    authenticated: req.session.authenticated || false,
    username: req.session.username || null
  });
});

// Signup page
app.get('/signup', (req, res) => {
  res.render('signup', {
    title: 'Sign Up',
    errorMessage: null
  });
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
    return res.render('signup', {
      title: 'Sign Up',
      errorMessage: validationResult.error.details[0].message
    });
  }

  const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
  const existingUser = await userCollection.findOne({ email });
  if (existingUser) {
    return res.render('signup', {
      title: 'Sign Up',
      errorMessage: 'User with that email already exists!'
    });
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  req.session.authenticated = true;
  req.session.username = name;
  req.session.email = email;
  req.session.cookie.maxAge = expireTime;

  res.redirect('/members');
});

// Login page
app.get('/login', (req, res) => {
  res.render('login', {
    title: 'Login',
    errorMessage: null
  });
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
    return res.render('login', {
      title: 'Login',
      errorMessage: validationResult.error.details[0].message
    });
  }

  const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
  const user = await userCollection.findOne({ email });
  if (!user) {
    return res.render('login', {
      title: 'Login',
      errorMessage: 'User not found'
    });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (validPassword) {
    req.session.authenticated = true;
    req.session.username = user.name;
    req.session.email = user.email;
    req.session.user = user;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
  } else {
    res.render('login', {
      title: 'Login',
      errorMessage: 'Incorrect password'
    });
  }
});

// Members page
app.get('/members', async (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect('/');
  }

  const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
  const user = await userCollection.findOne({ email: req.session.email });
  if (!user) {
    return res.redirect('/');
  }

  res.render('members', {
    title: 'Members',
    name: user.name
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect('/login');
}

// Middleware to check if user is admin
function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.user_type === 'admin') return next();
  res.status(403).render('403', { title: 'Forbidden' });
}

// Admin dashboard
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
  const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
  const users = await userCollection.find().toArray();
  res.render('admin', {
    title: 'Admin Dashboard',
    users
  });
});

// Promote user
app.get('/promote/:id', isAuthenticated, isAdmin, async (req, res) => {
  const userId = new ObjectId(req.params.id);
  const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
  await userCollection.updateOne({ _id: userId }, { $set: { user_type: 'admin' } });
  res.redirect('/admin');
});

// Demote user
app.get('/demote/:id', isAuthenticated, isAdmin, async (req, res) => {
  const userId = new ObjectId(req.params.id);
  const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
  await userCollection.updateOne({ _id: userId }, { $set: { user_type: 'user' } });
  res.redirect('/admin');
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('404', { title: 'Page Not Found' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

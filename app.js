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
  res.locals.authenticated = req.session.authenticated || false;
  res.locals.user = req.session.user || null;
  next();
});

// Routes

// Home page
app.get('/', (req, res) => {
  try {
        res.render('index', {
          title: 'Home',
          authenticated: req.session.authenticated || false,
          username: req.session.username || null,
          user: req.session.user || null
        });
  } catch (error) {
    console.error('Error rendering home page:', error);
    res.status(500).render('500', { title: 'Server Error' });
  }
});

// Signup page
app.get('/signup', (req, res) => {
  try {
    res.render('signup', {
      title: 'Sign Up',
      errorMessage: null
    });
  } catch (error) {
    console.error('Error rendering signup page:', error);
    res.status(500).render('500', { title: 'Server Error' });
  }
});

// Signup handler
app.post('/signup', async (req, res) => {
  try {
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
    await userCollection.insertOne({ name, email, password: hashedPassword, user_type: 'user' });

    req.session.authenticated = true;
    req.session.username = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).render('signup', {
      title: 'Sign Up',
      errorMessage: 'An unexpected error occurred. Please try again.'
    });
  }
});

// Login page
app.get('/login', (req, res) => {
  try {
    res.render('login', {
      title: 'Login',
      errorMessage: null
    });
  } catch (error) {
    console.error('Error rendering login page:', error);
    res.status(500).render('500', { title: 'Server Error' });
  }
});

// Login handler
app.post('/login', async (req, res) => {
  try {
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
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).render('login', {
      title: 'Login',
      errorMessage: 'An unexpected error occurred. Please try again.'
    });
  }
});

// Members page
app.get('/members', async (req, res) => {
  try {
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
  } catch (error) {
    console.error('Error rendering members page:', error);
    res.status(500).render('500', { title: 'Server Error' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  try {
    req.session.destroy();
    res.redirect('/');
  } catch (error) {
    console.error('Error during logout:', error);
    res.status(500).render('500', { title: 'Server Error' });
  }
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
  try {
    const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
    const users = await userCollection.find().toArray();
    res.render('admin', {
      title: 'Admin Dashboard',
      users,
      user: req.session.user
    });    
  } catch (error) {
    console.error('Error rendering admin dashboard:', error);
    res.status(500).render('500', { title: 'Server Error' });
  }
});

// Promote user
app.get('/promote/:id', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = new ObjectId(req.params.id);
    const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
    await userCollection.updateOne({ _id: userId }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');
  } catch (error) {
    console.error('Error promoting user:', error);
    res.status(500).render('500', { title: 'Server Error' });
  }
});

// Demote user
app.get('/demote/:id', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const userId = new ObjectId(req.params.id);
    const userCollection = database.db(MONGODB_DATABASE_USERS).collection('users');
    await userCollection.updateOne({ _id: userId }, { $set: { user_type: 'user' } });
    res.redirect('/admin');
  } catch (error) {
    console.error('Error demoting user:', error);
    res.status(500).render('500', { title: 'Server Error' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('404', { title: 'Page Not Found' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

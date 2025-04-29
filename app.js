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

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE_SESSIONS}?retryWrites=true&w=majority`,
  collectionName: 'sessions',
  crypto: { secret: process.env.MONGODB_SESSION_SECRET }
});

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}));

app.get('/', (req, res) => {
  res.render('index', { user: req.session });
});

app.get('/signup', (req, res) => {
  res.render('signup', { errorMessage: null });
});

app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const schema = Joi.object({
      name: Joi.string().max(50).required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required()
    });

    const { error } = schema.validate({ name, email, password });
    if (error) return res.render('signup', { errorMessage: error.details[0].message });

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const userCollection = database.collection('users');

    const existingUser = await userCollection.findOne({ email });
    if (existingUser) return res.render('signup', { errorMessage: 'User with that email already exists!' });

    const role = email.endsWith('@admin.com') ? 'admin' : 'user';

    await userCollection.insertOne({ name, email, password: hashedPassword, role });

    req.session.authenticated = true;
    req.session.username = name;
    req.session.role = role;
    req.session.cookie.maxAge = expireTime;

    res.redirect(role === 'admin' ? '/admin' : '/user');
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).render('signup', { errorMessage: 'Internal server error. Please try again.' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { errorMessage: null });
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().required()
    });

    const { error } = schema.validate({ email, password });
    if (error) return res.render('login', { errorMessage: error.details[0].message });

    const userCollection = database.collection('users');
    const user = await userCollection.findOne({ email });

    if (!user) return res.render('login', { errorMessage: 'User not found' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.render('login', { errorMessage: 'Incorrect password' });

    req.session.authenticated = true;
    req.session.username = user.name;
    req.session.role = user.role || 'user';
    req.session.cookie.maxAge = expireTime;

    res.redirect(user.role === 'admin' ? '/admin' : '/user');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).render('login', { errorMessage: 'Internal server error. Please try again.' });
  }
});

app.get('/user', (req, res) => {
  if (!req.session.authenticated || req.session.role !== 'user') return res.redirect('/');
  res.render('user', { username: req.session.username });
});

app.get('/admin', (req, res) => {
  if (!req.session.authenticated || req.session.role !== 'admin') return res.redirect('/');
  res.render('admin', { username: req.session.username });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.use((req, res) => {
  res.status(404).render('404');
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});

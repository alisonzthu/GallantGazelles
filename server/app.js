const express = require('express');
const path = require('path');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const passport = require('passport');
const app = express();
const PostgreSqlStore = require('connect-pg-simple')(session);
const dbConfig = require('../test/db/knex.js');
const auth = require('./routes/auth.js');
const router = require('./routes.js');
//avoid sessions for static resources
app.use(express.static(path.join(__dirname, '/../client/')));
app.use('/', express.static(path.join(__dirname, '/../client/')));
app.use('/companies', express.static(path.join(__dirname, '/../client/')));
app.use('/pitch', express.static(path.join(__dirname, '/../client/')));
app.use('/signup', express.static(path.join(__dirname, '/../client/')));
app.use('/signin', express.static(path.join(__dirname, '/../client/')));
app.use('/notfound', express.static(path.join(__dirname, '/../client/')));
app.use('/user', express.static(path.join(__dirname, '/../client/')));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));
const sessionOptions = {
	secret: 'secret',
	name: 'pitchmeio',
	store: new PostgreSqlStore({
		conString: dbConfig.config.connection
	}),
	cookie: {},
	resave: true,//resave true updates session on each page view. this avoids session expire
	saveUninitialized: true
};
app.use(session(sessionOptions));
app.use(passport.initialize());
app.use(passport.session());
//add cookie:
app.use((req, res, next) => {
	if(!req.session.pitchmeio) {
	   req.session.pitchmeio = 1;
	}
	console.log(passport.session()); 
  next();
});

app.use('/api', router);
app.use('/auth', auth);

app.listen(8080, function() {
	console.log('listening to 8080');
});

module.exports = app;
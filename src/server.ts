require('dotenv').config();

import * as express from 'express';
import * as passport from 'passport';
import * as azure_ad from 'passport-azure-ad';
import fetch from 'node-fetch';
import * as simple_oauth2 from 'simple-oauth2';
import { O_TRUNC } from 'constants';

// tslint:disable-next-line: no-var-requires
require('dotenv').config();

const baseUrl = process.env.BASE_URL || 'http://localhost:3000/';
const redirectPath = 'auth/openid/return';
const port = process.env.PORT || '3000';

const oauth = simple_oauth2.create({
  client: {
    id: process.env.APP_ID,
    secret: process.env.APP_SECRET,
  },
  auth: {
    tokenHost: 'https://login.microsoftonline.com/common',
    authorizePath: '/oauth2/v2.0/authorize', 
    tokenPath: '/oauth2/v2.0/token', 
  }
});

const azureStrategyOptions: azure_ad.IOIDCStrategyOptionWithRequest = {
  identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
  clientID: process.env.APP_ID,
  clientSecret: process.env.APP_SECRET,
  responseType: 'code id_token',
  responseMode: 'form_post',
  redirectUrl: baseUrl + redirectPath,
  allowHttpForRedirectUrl: true, // in production make false
  validateIssuer: false, // in production make true
  isB2C: false,
  issuer: null,
  passReqToCallback: true,
  scope: ['profile', 'offline_access', 'https://graph.microsoft.com/user.readwrite'], // remove offline_access if you only want the app to be functional during login
  loggingLevel: 'info',
  nonceLifetime: null, // defaults to 3600 seconds
  nonceMaxAmount: 10, // 10 is default
  useCookieInsteadOfSession: false,
  cookieEncryptionKeys: null, // not required if useCoookieInsteadOfSession is false
  clockSkew: null, // 
};

async function processAzureStrategy(
  req: express.Request,
  iss: string,
  sub: string,
  profile: azure_ad.IProfile,
  jwtClaims: any,
  access_token: string,
  refresh_token: string,
  params: any,
  done: azure_ad.VerifyCallback) {

  if (!profile.oid) {
    return done(new Error('No oid found'), null);
  }
  process.nextTick(async () => {
    return done(null, { ...profile, oauthToken: params }); // Done and include OauthToken in the profile.
  });
}

// Augument Passport's request.user with the Azure AD oauthToken
declare global {
  namespace Express {
    interface User {
      oauthToken: any;
      [key: string]: any;

    }
  }
}

passport.use(new azure_ad.OIDCStrategy(azureStrategyOptions, processAzureStrategy));

// Configure Passport authenticated session persistence.
//
// In order to restore authentication state across HTTP requests, Passport needs
// to serialize users into and deserialize users out of the session.  In a
// production-quality application, this would typically be as simple as
// supplying the user ID when serializing, and querying the user record by ID
// from the database when deserializing.  However, due to the fact that this
// example does not have a database, the complete Azure AD profile is serialized
// and deserialized.

passport.serializeUser(function (user, cb) {
  cb(null, user);
});

passport.deserializeUser(async function (obj: any, cb) {
  let managedAccessToken = oauth.accessToken.create(obj.oauthToken);
  if (managedAccessToken.expired()) managedAccessToken = await managedAccessToken.refresh(); // could do this check when you are doing calls but this should help keep it up to date in the session state when serialized
  cb(null, {... obj, oauthToken: managedAccessToken.token});
});

// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', require('path').join(__dirname, '../views'));
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('morgan')('combined'));
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('cookie-parser')()); // required by Azure-AD return parsing
app.use(require('express-session')({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

// Define routes.
app.get('/',
  function (req, res) {
    res.render('home', { user: req.user });
  });

app.get('/login',
  function (req, res) {
    res.render('login');
  });

app.get('/login/azure-ad',
  passport.authenticate('azuread-openidconnect'));


app.get('/' + redirectPath,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function (req, res) {
    res.redirect('/');
  });

app.post('/' + redirectPath,
  passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }),
  function (req, res) {
    res.redirect('/');
  });

app.get('/logout',
  function (req, res) {
    req.logout();
    res.redirect('/');
  });

app.get('/profile',
  require('connect-ensure-login').ensureLoggedIn(),
  async (req, res, next) => {
    const response = await fetch('https://graph.microsoft.com/v1.0/me', { headers: { 'Authorization': `Bearer ${req.user.oauthToken.access_token}` } });
    if (!response.ok) return next(response.statusText);
    let profile = await response.json();
    res.render('profile', { user: profile });
    return next();
  });

app.listen(port);

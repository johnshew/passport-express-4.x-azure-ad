"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
require('dotenv').config();
const express = require("express");
const passport = require("passport");
const azure_ad = require("passport-azure-ad");
const node_fetch_1 = require("node-fetch");
// tslint:disable-next-line: no-var-requires
require('dotenv').config();
const baseUrl = process.env.BASE_URL || 'http://localhost:3000/';
const redirectPath = 'auth/openid/return';
const port = process.env.PORT || '3000';
const azureStrategyOptions = {
    identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    responseType: 'code id_token',
    responseMode: 'form_post',
    redirectUrl: baseUrl + redirectPath,
    allowHttpForRedirectUrl: true,
    validateIssuer: false,
    isB2C: false,
    issuer: null,
    passReqToCallback: true,
    scope: ['profile', 'offline_access', 'https://graph.microsoft.com/user.readwrite'],
    loggingLevel: 'info',
    nonceLifetime: null,
    nonceMaxAmount: 10,
    useCookieInsteadOfSession: false,
    cookieEncryptionKeys: null,
    clockSkew: null,
};
async function processAzureStrategy(req, iss, sub, profile, jwtClaims, access_token, refresh_token, oauthToken, done) {
    if (!profile.oid) {
        return done(new Error('No oid found'), null);
    }
    process.nextTick(async () => {
        return done(null, { ...profile, oauthToken }); // Done and include OauthToken in the profile.
    });
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
    console.log(user);
    cb(null, user);
});
passport.deserializeUser(function (obj, cb) {
    console.log(obj);
    cb(null, obj);
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
app.get('/', function (req, res) {
    res.render('home', { user: req.user });
});
app.get('/login', function (req, res) {
    res.render('login');
});
app.get('/login/azure-ad', passport.authenticate('azuread-openidconnect'));
app.get('/' + redirectPath, passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }), function (req, res) {
    res.redirect('/');
});
app.post('/' + redirectPath, passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }), function (req, res) {
    res.redirect('/');
});
app.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});
app.get('/profile', require('connect-ensure-login').ensureLoggedIn(), async (req, res, next) => {
    const response = await node_fetch_1.default('https://graph.microsoft.com/v1.0/me', { headers: { 'Authorization': `Bearer ${req.user.oauthToken.access_token}` } });
    if (!response.ok)
        return next(response.statusText);
    let profile = await response.json();
    res.render('profile', { user: profile });
    return next();
});
app.listen(process.env['PORT'] || 3000);
//# sourceMappingURL=server.js.map
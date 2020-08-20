"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv = require("dotenv");
const console_1 = require("console");
dotenv.config();
console_1.assert(process.env.APP_ID && process.env.APP_SECRET, "Must have APP_ID and APP_SECRET defined");
// Express with passport-azure-ad
const express = require("express");
const passport = require("passport");
const azure_ad = require("passport-azure-ad");
const connect_ensure_login = require("connect-ensure-login");
const ensureLoggedIn = connect_ensure_login.ensureLoggedIn();
// Enable Microsoft Graph calls
const node_fetch_1 = require("node-fetch");
const simple_oauth2 = require("simple-oauth2"); // for token refresh management
const redirectPath = 'auth/openid/return';
const port = process.env.PORT || '8080';
const baseUrl = process.env.BASE_URL || 'http://localhost:' + port;
const azureStrategyOptions = {
    identityMetadata: 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration',
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    responseType: 'code id_token',
    responseMode: 'form_post',
    redirectUrl: baseUrl + redirectPath,
    allowHttpForRedirectUrl: process.env.ALLOW_HTTP === 'true',
    validateIssuer: false,
    isB2C: false,
    // issuer: process.env.ISSUER,
    passReqToCallback: true,
    scope: ['profile', 'offline_access', 'https://graph.microsoft.com/user.read'],
    loggingLevel: 'info',
    nonceLifetime: null,
    nonceMaxAmount: 10,
    useCookieInsteadOfSession: false,
    cookieEncryptionKeys: null,
    clockSkew: null,
};
async function processAzureStrategy(req, iss, sub, profile, jwtClaims, access_token, refresh_token, params, done) {
    if (req.user) {
        return done(null, { ...req.user, oauthToken: params });
    }
    if (!profile.oid) {
        return done(new Error('No oid found'), null);
    }
    process.nextTick(async () => {
        return done(null, { ...profile, oauthToken: params }); // Done and include OauthToken in the profile.
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
passport.serializeUser(async (user, cb) => {
    cb(null, user);
});
passport.deserializeUser(async (obj, cb) => {
    let managedAccessToken = oauth.accessToken.create(obj.oauthToken);
    // could do the following check when you are doing calls but this should help keep it up to date in the session state when serialized
    if (managedAccessToken.expired()) {
        managedAccessToken = await managedAccessToken.refresh();
    }
    cb(null, { ...obj, oauthToken: managedAccessToken.token });
});
const oauth = simple_oauth2.create({
    client: {
        id: process.env.APP_ID,
        secret: process.env.APP_SECRET,
    },
    auth: {
        tokenHost: 'https://login.microsoftonline.com/common',
        authorizePath: '/oauth2/v2.0/authorize',
        tokenPath: '/oauth2/v2.0/token',
    },
});
// Create a new Express application.
const app = express();
// Configure view engine to render EJS templates.
app.set('views', require('path').join(__dirname, '../views'));
app.set('view engine', 'ejs');
// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.n
app.use(require('morgan')('combined'));
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('cookie-parser')()); // required by Azure-AD return parsing
app.use(require('express-session')({ secret: process.env.COOKIE_SECRET, resave: false, saveUninitialized: false }));
// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());
// Define routes.
app.get('/', (req, res, next) => {
    res.render('home', { user: req.user });
});
app.get('/login', (req, res, next) => {
    res.render('login');
    return next();
});
app.get('/login/azure-ad', passport.authenticate('azuread-openidconnect'));
app.get('/' + redirectPath, passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }), (req, res, next) => {
    res.redirect('/');
    return next();
});
app.post('/' + redirectPath, passport.authenticate('azuread-openidconnect', { failureRedirect: '/login' }), (req, res, next) => {
    res.redirect('/');
    return next();
});
app.get('/logout', (req, res, next) => {
    req.logout();
    res.redirect('/');
    return next();
});
app.get('/profile', ensureLoggedIn, async (req, res, next) => {
    // Keeping things simple we make a direct call to the graph. 
    // Note that the /me node contains a preferredLanguage field that is not in the oath profile.
    const response = await node_fetch_1.default('https://graph.microsoft.com/v1.0/me', { headers: { Authorization: `Bearer ${req.user.oauthToken.access_token}` } });
    if (!response.ok) {
        return next(response.statusText);
    }
    const profile = await response.json();
    res.render('profile', { user: profile });
    return next();
});
app.listen(port);
//# sourceMappingURL=server.js.map
This example demonstrates how to use [Express](http://expressjs.com/) 4.x and
[Passport](http://passportjs.org/) to authenticate users using Azure AD
and then access the Microsoft Graph APIs.  

## Instructions

To install this example on your computer, clone the repository, install the
dependencies, and build it.

```bash
$ git clone https://github.com/johnshew/passport-express-4.x-azure-ad.git
$ cd passport-express-4.x-azure-ad
$ npm install
$ npm build
```

Set environment variables for APP_ID and APP_SECRET or create a .env file.  See AAD app registration.

Then start the server.

```bash
$ node dist/server.js
```

Open a web browser and navigate to [http://localhost:8080/](http://127.0.0.1:8080/)
to see the example in action. 

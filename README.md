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

Then start the server.

```bash
$ node dist/server.js
```

Open a web browser and navigate to [http://localhost:3000/](http://127.0.0.1:3000/)
to see the example in action. 

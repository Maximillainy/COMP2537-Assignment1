require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

const Joi = require("joi");

const port = process.env.PORT || 3000;

// expires in 1 hour
const expireTime = 1000 * 60 * 60;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        res.send(`
            Hello, ${req.session.username}!
            <br>
            <a href="/members">Members Area</a>
            <br>
            <a href="/logout">Sign Out</a>
        `);
    } else {
        res.send(`
            <a href="/createUser"><button>Sign Up</button></a>
            <br>
            <a href="/login"><button>Log In</button></a>
        `);
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    } else {
        const randomImage = Math.floor(Math.random() * 3) + 1;
        res.send(`
            Hello, ${req.session.username}.
            <br>
            <img style="width: 200px; height: 200px;" src="image${randomImage}.jpg" alt="Random image ${randomImage}" />
            <br>
            <a href="/logout">Sign Out</a>
        `);
    }
});

app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
        const errorMessage = validationResult.error.details[0].message;
        res.send(`
        ${errorMessage}
        <br>
        <a href="/createUser">Try again</a>
        `);
        return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email, password: hashedPassword});
	console.log("Inserted user");

    res.redirect('/members');
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
        const errorMessage = validationResult.error.details[0].message;
	   console.log(validationResult.error);
	   res.send(`
        ${errorMessage}
        <br>
        <a href="/login">Try again</a>
        `);
	   return;
	}

	const result = await userCollection.findOne({email});

	console.log(result);
	if (!result) {
		console.log("user not found");
        res.send(`
         invalid email
         <br>
         <a href="/login">Try again</a>
         `);
        return;
	}
	if (await bcrypt.compare(password, result.password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = result.username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
        res.send(`
         invalid password
         <br>
         <a href="/login">Try again</a>
         `);
		return;
	}
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 


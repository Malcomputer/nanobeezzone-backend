const MongoClient = require('mongodb').MongoClient;
const jwt = require('jsonwebtoken');
const express = require('express');
const crypto = require('crypto');
const app = express();
const port = process.env.PORT || 3001;
require('dotenv').config();

app.use(express.json());

const getHashedPassword = password => {
	const sha256 = crypto.createHash('sha256');
	return sha256.update(password).digest('base64');
}

const authenticateJWT = (req, res, next) => {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		const token = authHeader.split(' ')[1];
		jwt.verify(token, process.env.ATS, (err, user) => {
			if (err) return res.sendStatus(403);
			req.user = {...user, issuedAt: parseInt(`${user.iat}000`), iat: undefined};
			next();
		});
	} else res.sendStatus(401);
};

const client = new MongoClient(process.env.DB, {useNewUrlParser: true, useUnifiedTopology: true});

app.get('/', (req, res) => {
	res.send('Server Running');
});

app.get('/user', authenticateJWT, (req, res) => {
	res.send(req.user);
});

app.post('/signup', (req, res) => {
	if (!req.body.username || !req.body.password || !req.body.name) {
		res.status(401).json({error: {message: 'All input fields required!', status: res.statusCode}});
	}
	client.connect(() => {
		const userCollection = client.db("nanobeezzone").collection("users");
		const newUser = {...req.body, password: getHashedPassword(req.body.password)};
		userCollection.findOne({username: newUser.username}, (err, result) => {
			if (err) throw err;
			if (result) res.status(401).json({error: {message: 'Username already exist!', status: res.statusCode}});
			else userCollection.insertOne(newUser).then(() => res.status(201).json({success: {message: 'New User created!', status: res.statusCode}}));
		});
	});
});

app.post('/login', (req, res) => {
	if (!req.body.username || !req.body.password) {
		res.status(401).json({error: {message: 'All input fields required!', status: res.statusCode}});
	}
	client.connect(() => {
		const userCollection = client.db("nanobeezzone").collection("users");
		userCollection.findOne({username: req.body.username, password: getHashedPassword(req.body.password)}, ((error, result) => {
			if (error) throw error;
			if (result) {
				const accessToken = jwt.sign({username: result.username, name: result.name}, process.env.ATS);
				res.json({accessToken});
			} else res.status(401).send('Username or password incorrect');
		}));
	});
});

app.listen(port, () => console.log(`Listening on http://localhost:${port}/`));
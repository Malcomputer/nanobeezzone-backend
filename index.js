const MongoClient = require('mongodb').MongoClient;
const jwt = require('jsonwebtoken');
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const app = express();
const port = process.env.PORT || 3001;
const io = require('socket.io')(require('http').Server(app).listen(port, () => console.log(`Listening on http://localhost:${port}/`)));
require('dotenv').config();

app.use(express.static('public'));
app.use(express.json());
app.use(cors());
app.use(function (req, res, next) {
	res.header("Access-Control-Allow-Origin", "*");
	res.header(
		"Access-Control-Allow-Headers",
		"Origin, X-Requested-With, Content-Type, Accept"
	);
	res.header(
		"Access-Control-Allow-Methods",
		"GET, POST, OPTIONS, PUT, PATCH, DELETE"
	);
	next();
});

let activeUsers = {
	getSocket(user) {
		if (this.hasOwnProperty(user)) return this[user];
		else return this[this.getId(user)];
	},
	setSocket(id, socket) {
		this[id] = socket;
	},
	removeSocket(socketId) {
		delete this[this.getId(socketId)];
	},
	getId(user) {
		return Object.keys(this).filter(k => (k.toLowerCase().indexOf(user.toLowerCase()) > -1) || (user.toLowerCase().indexOf(k.toLowerCase()) > -1))[0];
	},
	getUsername() {}
};

const getHashedPassword = password => {
	const sha256 = crypto.createHash('sha256');
	return sha256.update(password).digest('base64');
}

const authenticateJWT = (req, res, next) => {
	const authHeader = req.headers.authorization;
	if (authHeader) {
		const token = authHeader.split(' ')[1];
		jwt.verify(token, process.env.ATS, (err, user) => {
			if (err) return res.status(403).json({error: {message: err, status: res.statusCode}});
			delete user.iat;
			req.user = user;
			next();
		});
	} else res.status(401).json({error: {message: 'Missing Authorization header', status: res.statusCode}});
};

const client = new MongoClient(process.env.DB, {useNewUrlParser: true, useUnifiedTopology: true});

app.get('/user', authenticateJWT, (req, res) => {
	res.send(req.user);
});

app.get('/users', authenticateJWT, (req,res) => {
	client.connect(() => {
		const userCollection = client.db("nanobeezzone").collection("users");
		userCollection.find({}).toArray().then(users => users.filter(user =>  delete user.password)).then(users => res.json(users));
	});
});

app.get('/user/:username', authenticateJWT, (req, res) => {
	client.connect(() => {
		const userCollection = client.db("nanobeezzone").collection("users");
		userCollection.findOne({username: req.params.username}, ((err, result) => {
			if (err || result === null) return res.status(404).json({error: {message: 'User not found', status: res.statusCode}});
			if (result.username) res.json({...result, password: undefined});
		}));
	});
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
		userCollection.findOne({username: req.body.username, password: getHashedPassword(req.body.password)}, ((error, user) => {
			if (error) throw error;
			if (user) {
				const accessToken = jwt.sign({username: user.username, name: user.name, id: user._id}, process.env.ATS);
				res.json({...user, password: undefined, accessToken});
			} else res.status(401).json({error: {message: 'Username or password incorrect', status: res.statusCode}});
		}));
	});
});

app.get('/messages/:user', authenticateJWT, (req, res) => {
	client.connect(() => {
		const messagesCollection = client.db("nanobeezzone").collection("messages");
		messagesCollection.find({message_id:{$regex: req.params.user}}).toArray().then(messages => res.json(messages));
	});
});

app.get('/message/:receiver/:sender', authenticateJWT, (req, res) => {
  client.connect(async () => {
  	const messagesCollection = client.db("nanobeezzone").collection("messages");
  	const userOne = await messagesCollection.find({"author.username": req.params.sender, receiver: req.params.receiver}).toArray();
  	const userTwo = await messagesCollection.find({"author.username": req.params.receiver, receiver: req.params.sender}).toArray();
  	res.json([...userOne, ...userTwo]);
  });
});

app.post('/message', authenticateJWT, (req, res) => {
  if (!req.body.newMessage) {
  	res.status(401).json({error:{message: 'Content required', status: res.statusCode}});
  }
  client.connect(() => {
	  const messagesCollection = client.db("nanobeezzone").collection("messages");
		let receiver = activeUsers.getSocket(req.body.newMessage.receiver);
		if (receiver) receiver.emit('send-message', req.body.newMessage);
	  messagesCollection.insertOne(req.body.newMessage).then(() => res.status(201).json({success: {message: 'Message Sent!', status: res.statusCode}}));
  });
});

io.on('connection', socket => {
	socket.on('active-user', user => activeUsers.setSocket(`${user}:${socket.id}`, socket));
	socket.on('disconnect', () => activeUsers.removeSocket(socket.id));
});

app.get('*', (req, res) => res.sendFile(__dirname + '/public/index.html'));

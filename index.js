const MongoClient = require('mongodb').MongoClient;
const jwt = require('jsonwebtoken');
const express = require('express');
const crypto = require('crypto');
const app = express();
const port = process.env.PORT || 3001;
app.use(express.json());

const getHashedPassword = password => {
	const sha256 = crypto.createHash('sha256');
	return sha256.update(password).digest('base64');
}

const client = new MongoClient(process.env.DB, {useNewUrlParser: true, useUnifiedTopology: true});

app.get('/', (req, res) => {
	res.send('Server Running');
});

app.listen(port, () => console.log(`Listening on http://localhost:${port}/`));
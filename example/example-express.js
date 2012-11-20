var OAuth2Provider = require('../index'),
	express = require('express'),
	MemoryStore = express.session.MemoryStore;

var oauthProvider = new OAuth2Provider("signing-secret");

// client_id and/or redirect_uri is missing
oauthProvider.on('authorizeParamMissing', function(req, res, callback) {
	res.writeHead(400);
	res.end("missing param");
});

// log the user in (if not already)
oauthProvider.on('enforceLogin', function(req, res, authorizeUrl, callback) {
	if(req.session.user) {
		callback(req.session.user);
	} else {
		res.writeHead(303, {Location: '/login?next=' + encodeURIComponent(authorizeUrl)});
		res.end();
	}
});

// let the user explicitly grant access to the app 
oauthProvider.on('authorizeForm', function(req, res, clientId, authorizeUrl) {
	res.end('<html>this app wants to access your account... <form method="post" action="' + authorizeUrl + '"><button name="allow">Allow</button></form>');
});

// response_type parameter is not "token" or "code" 
oauthProvider.on('invalidResponseType', function(req, res, callback) {
	res.writeHead(400);
	res.end("invalid response type");
});

// code or token wrong 
oauthProvider.on('accessDenied', function(req, res, callback) {
	res.json(401, {error:"access denied"});
});

// create the access token
oauthProvider.on('createAccessToken', function(userId, clientId, callback) {
	/*
		Any string is allowed as token. Therefor JSON is possible as well. While implicit tokens
		are recommended it's still good, the have some kind of basic validation so you don't need
		to lookup every "obviously" invalid token. Also you could keep blocked client id's in memory.

		If you decide to have token's that expire, you should put this in the token as well.

		Here you should also save the token in the data base.

		var tokenDataString = {
			clientId:clientId,
			expire:1353334692885,
			token:"ABC123" // saved in the db for lookup
		}

		or

		var tokenDataString = {
			token:"ABC123" // saved in the db for lookup
		}

		or even

		var tokenDataString =  "ABC123"; // saved in the db for lookup

		The tokenDataString will be encrypted with the "signing-secret".

	*/
	callback("test-tooken");
});

oauthProvider.on('createGrant', function(req, clientId, callback) {
	/*
		The grantString will be encrypted with the "signing-secret".

		Pretty much the same applies as for create access token.
	*/
	callback("ABC123");
});

// chech if grant is valid
oauthProvider.on('lookupGrant', function(clientId, clientSecret, code, res, callback) {
	/*
		- check if grant exists
		- check if grant match to clientId
		- check if clientSecret match with client
		- callback with userId if everything is fine
	*/
	callback("userId");
});

var app = express();

// app.use(express.logger());
app.use(express.bodyParser());
app.use(express.query());
app.use(express.cookieParser());
app.use(express.session({store: new MemoryStore({reapInterval: 5 * 60 * 1000}), secret: 'abracadabra'}));
app.use(oauthProvider.oauth());

app.get('/', function(req, res, next) {
	console.dir(req.session);
	res.end('home, logged in? ' + !!req.session.user);
});

app.get('/login', function(req, res, next) {
	if(req.session.user) {
		res.writeHead(303, {Location: '/'});
		return res.end();
	}

	var next_url = req.query.next ? req.query.next : '/';
	res.end('<html><form method="post" action="/login"><input type="hidden" name="next" value="' + next_url + '"><input type="text" placeholder="username" name="username"><input type="password" placeholder="password" name="password"><button type="submit">Login</button></form>');
});

app.post('/login', function(req, res, next) {
	req.session.user = req.body.username;
	res.writeHead(303, {Location: req.body.next || '/'});
	res.end();
});

app.get('/logout', function(req, res, next) {
	req.session.destroy(function(err) {
		res.writeHead(303, {Location: '/'});
		res.end();
	});
});

app.get('/protected_resource', function(req, res, next) {
	if(req.query.access_token) {
		var accessToken = req.query.access_token;
		/*
			Here it's on you to validate the token
		*/
		res.json(access_token);
	} else {
		res.writeHead(403);
		res.end('no token found');
	}
});

app.listen(8081);


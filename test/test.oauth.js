var should = require('should'),
	OAuth2Provider = require('../index');

// mocha -t 5000 -R "spec" -b test.oauth.js

describe('oauth2 flow', function(){

	var tokenData = [1, "ABC123", "AAABBBCCC"],
		expectedRedirectUrl = "/oauth/authorize?client_id=1&redirect_uri=lala.com&x_user_id=XVj0tqUQTkOO5bH-77n2XA",
		authUrl = "authorize?client_id=1&redirect_uri=lala.com&x_user_id=XVj0tqUQTkOO5bH-77n2XA",
		expectedToken = "oYbuYeiBUAHNbBxfTlSb9S8JEcg_2lWO_DoZBD9GVZY",
		expectedCode = "k7BsPCag8vS4KWbl3m80xw";

	var oauthProvider = new OAuth2Provider("bar");

	oauthProvider.on('authorizeParamMissing', function(req, res, callback) {
		res.json(400, {error:"missing param"});
	});

	oauthProvider.on('enforceLogin', function(req, res, authorizeUrl, callback) {
		callback("test@cnn.com");
	});

	oauthProvider.on('authorizeForm', function(req, res, clientId, authorizeUrl) {
		res.json({url:authorizeUrl});
	});

	oauthProvider.on('invalidResponseType', function(req, res, callback) {
		res.json(400, {error:"invalid response type"});
	});

	oauthProvider.on('accessDenied', function(req, res, callback) {
		res.json(401, {error:"access denied"});
	});

	oauthProvider.on('createAccessToken', function(userId, clientId, callback) {
		callback(JSON.stringify(tokenData));
	});

	oauthProvider.on('createGrant', function(req, clientId, callback) {
		callback("ABC123");
	});

	oauthProvider.on('lookupGrant', function(clientId, clientSecret, code, res, callback) {
		callback();
	});

	function makeRequest(option, callback){
		var endpoint = option.uri.split("?")[0],
			query = getQuery(option.uri);

		var req = {
			method:option.method,
			url:"/oauth/" + option.uri,
			query:query,
			body:option.body || {}
		};

		var res = {
			json:function(status, data){
				var code = 200,
					body;
				if(typeof(status) === "number") {
					code = status;
					body = data;
				} else {
					body = status;
				}
				if(typeof(body) !== "object"){
					body = JSON.parse(body);
				}
				callback(null, {statusCode:code}, body);
			},
			writeHead:function(code, headers){
				callback(null, {statusCode:code, headers:headers});
			},
			end:function(){}
		};

		oauthProvider.oauth()(req, res);
	}

	function getQuery(url){
		if(url.indexOf("?") === -1) {
			return {};
		}
		var qs = url.substring(url.indexOf('?') + 1).split('&');
		for(var i = 0, result = {}; i < qs.length; i++){
			qs[i] = qs[i].split('=');
			result[qs[i][0]] = qs[i][1];
		}
		return result;
	}

	describe('GET /authorize (missing param)', function(){

		it('run', function(done){
			var expectedResponse = {error:"missing param"};

			var option = {
				method:"GET",
				uri:"authorize"
			};

			makeRequest(option, function(err, response, body){
				if(err || response.statusCode !== 400){
					return done(err || new Error(response.statusCode));
				}
				body.should.eql(expectedResponse);
				done();
			});
		});

	});

	describe('GET /authorize (ok)', function(){

		it('run', function(done){
			var expectedResponse = {url: expectedRedirectUrl};

			var option = {
				method:"GET",
				uri:"authorize?client_id=1&redirect_uri=lala.com"
			};

			makeRequest(option, function(err, response, body){
				if(err || response.statusCode !== 200){
					return done(err || new Error(response.statusCode));
				}
				body.should.eql(expectedResponse);
				done();
			});
		});

	});

	describe('POST /authorize (invalid response type)', function(){

		it('run', function(done){
			var expectedResponse = {error:"invalid response type"};

			var option = {
				method:"POST",
				uri:authUrl+"&response_type=wtf",
				body:{
					allow:true
				}
			};

			makeRequest(option, function(err, response, body){
				if(err || response.statusCode !== 400){
					return done(err || new Error(response.statusCode));
				}
				body.should.eql(expectedResponse);
				done();
			});
		});

	});

	describe('POST /authorize (x_user_id wrong)', function(){

		it('run', function(done){
			var expectedResponse = {error:"access denied"};

			var option = {
				method:"POST",
				uri:authUrl + "extra_trash_that_breaks_x_user_id",
				body:{
					allow:true
				}
			};

			makeRequest(option, function(err, response, body){
				if(err || response.statusCode !== 401){
					return done(err || new Error(response.statusCode));
				}
				body.should.eql(expectedResponse);
				done();
			});
		});

	});

	describe('POST /authorize (token, ok)', function(){

		it('run', function(done){

			var option = {
				method:"POST",
				uri:authUrl
			};

			makeRequest(option, function(err, response, body){
				if(err || response.statusCode !== 303){
					return done(err || new Error(response.statusCode));
				}
				var token = response.headers.Location.split("#access_token=")[1];
				token.should.equal(expectedToken);
				done();
			});
		});

	});

	describe('POST /authorize (code, ok)', function(){

		it('run', function(done){

			var option = {
				method:"POST",
				uri:authUrl+"&response_type=code",
				body:{
					allow:true
				}
			};

			makeRequest(option, function(err, response, body){
				if(err || response.statusCode !== 303){
					return done(err || new Error(response.statusCode));
				}
				var code = response.headers.Location.split("?code=")[1];
				code.should.equal(expectedCode);
				done();
			});
		});

	});

	describe('POST /access_token (invalid code)', function(){

		it('run', function(done){
			var expectedResponse = { error: 'access denied' } ;

			var option = {
				method:"POST",
				uri:"access_token",
				body:{
					clientId:1,
					clientSecret:"lala",
					redirectUri:"lala.com",
					code:"WTF_code"
				}
			};

			makeRequest(option, function(err, response, body){
				if(err || response.statusCode !== 401){
					return done(err || new Error(response.statusCode));
				}
				body.should.eql(expectedResponse);
				done();
			});
		});

	});

	describe('POST /access_token (ok)', function(){

		it('run', function(done){

			var option = {
				method:"POST",
				uri:"access_token",
				body:{
					clientId:1,
					clientSecret:"lala",
					redirectUri:"lala.com",
					code:expectedCode
				}
			};

			makeRequest(option, function(err, response, body){
				if(err || response.statusCode !== 200){
					return done(err || new Error(response.statusCode));
				}
				body.access_token.should.equal(expectedToken);
				done();
			});
		});

	});

	describe('POST /validate_token (invalid token)', function(){

		it('run', function(done){

			oauthProvider.validateToken("WTF_token", function(err, tokenData){
				should.exist(err);
				done();
			});

		});

	});

	describe('POST /validate_token (ok)', function(){

		it('run', function(done){
			var expectedResponse = [1,"ABC123","AAABBBCCC"];

			oauthProvider.validateToken(expectedToken, function(err, tokenData){
				tokenData.should.eql(tokenData);
				done();
			});

		});

	});

});
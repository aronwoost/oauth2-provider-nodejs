var EventEmitter = require('events').EventEmitter,
	crypto = require('crypto');

function OAuth2Provider(signKey) {
	this.cryptSecret = signKey;
}

OAuth2Provider.prototype = new EventEmitter();

OAuth2Provider.prototype._encodeUrlSaveBase64 = function(str) {
	return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
};

OAuth2Provider.prototype._decodeUrlSaveBase64 = function(str) {
	str = (str + '===').slice(0, str.length + (str.length % 4));
	return str.replace(/-/g, '+').replace(/_/g, '/');
};

OAuth2Provider.prototype._encrypt = function(data) {
	var cipher = crypto.createCipher("aes256", this.cryptSecret);
	var str = cipher.update(data, 'utf8', 'base64') + cipher.final('base64');
	str = this._encodeUrlSaveBase64(str);
	return str;
};

OAuth2Provider.prototype._decrypt = function(data) {
	var str = this._decodeUrlSaveBase64(data);
	var decipher = crypto.createDecipher("aes256", this.cryptSecret);
	str = decipher.update(str, 'base64', 'utf8') + decipher.final('base64');
	return str;
};

OAuth2Provider.prototype.validateToken = function(token, callback) {
	var self = this,
		tokenData;

	try {
		tokenData = self._decrypt(token);
	} catch(e) {
		return callback(new Error("decrypting token failed"));
	}

	callback(null, tokenData);
};

OAuth2Provider.prototype._get_oauth = function(req, res, next) {
	var self = this,
		clientId = req.query.client_id,
		redirectUri = req.query.redirect_uri,
		responseType = req.query.response_type || 'token';

	if(!clientId || !redirectUri) {
		return self.emit('authorizeParamMissing', req, res, next);
	}

	var authorizeUrl = req.url;

	self.emit('enforceLogin', req, res, authorizeUrl, function(userId) {
		self.emit('shouldSkipAllow', userId, clientId, function(skip, tokenDataStr) {
			if(skip) {
				self._validateThings(req, res, clientId, redirectUri, responseType, function(){
					if(tokenDataStr) {
						self._redirectWithToken(tokenDataStr, redirectUri, res);
					}else{
						self.emit('createAccessToken', userId, clientId, function(tokenDataStr) {
							self._redirectWithToken(tokenDataStr, redirectUri, res);
						});
					}
				});
			}else{
				authorizeUrl += '&x_user_id=' + self._encrypt(userId);
				self.emit('authorizeForm', req, res, clientId, authorizeUrl);
			}
		});
	});
};

OAuth2Provider.prototype._post_oauth = function(req, res, next) {
	var self = this;

	var clientId = req.query.client_id,
		url = req.query.redirect_uri,
		responseType = req.query.response_type || 'token',
		state = req.query.state,
		xUserId = req.query.x_user_id;

	self._validateThings(req, res, clientId, url, responseType, function(){

		if(!req.body.allow) {
			return self._redirectError(res, responseType, url, "access_denied");
		}

		if('token' === responseType) {
			var userId;
			try {
				userId = self._decrypt(xUserId);
			} catch(e) {
				return self.emit('parameterError', req, res);
			}

			self.emit('createAccessToken', userId, clientId, function(tokenDataStr) {
				var atok = self._encrypt(tokenDataStr);
				url += "#access_token=" + atok;
				res.writeHead(303, {Location: url});
				res.end();
			});
		} else {
			self.emit('createGrant', req, clientId, function(codeStr) {
				codeStr = self._encrypt(codeStr);
				url += "?code=" + codeStr;

				// pass back anti-CSRF opaque value
				if(state) {
					url += "&state=" + state;
				}

				res.writeHead(303, {Location: url});
				res.end();
			});
		}
	});
};

OAuth2Provider.prototype._redirectWithToken = function(tokenDataStr, redirectUri, res) {
	var atok = this._encrypt(tokenDataStr);
	redirectUri += "#access_token=" + atok;
	res.writeHead(303, {Location: redirectUri});
	return res.end();
};

OAuth2Provider.prototype._validateThings = function(req, res, clientId, redirectUri, responseType, callback) {
	var self = this;
	if(responseType !== "code" && responseType !== "token") {
		return self.emit('responseTypeError', req, res);
	}
	self.emit('validateClientIdAndRedirectUri', clientId, redirectUri, req, res, callback);
};

OAuth2Provider.prototype._redirectError = function(res, responseType, url, error) {
	var sep = responseType === "token" ? "#" : "?";
	res.writeHead(303, {Location: url + sep + "error=" + error});
	return res.end();
};

OAuth2Provider.prototype._post_access_token = function(req, res, next) {
	var self = this,
		clientId = req.body.client_id,
		clientSecret = req.body.client_secret,
		redirectUri = req.body.redirect_uri,
		code = req.body.code;

	try {
		code = self._decrypt(code);
	} catch(e) {
		return self.emit('accessDenied', req, res);
	}

	self.emit('lookupGrant', clientId, clientSecret, code, res, function(userId) {
		self.emit('createAccessToken', userId, clientId, function(tokenDataStr) {
			var atok = self._encrypt(tokenDataStr);
			res.json({access_token:atok});
		});
	});
};

OAuth2Provider.prototype.oauth = function() {
	var self = this;
	return function(req, res, next) {
		var uri = ~req.url.indexOf('?') ? req.url.substr(0, req.url.indexOf('?')) : req.url;
		if(req.method === 'GET' && uri === '/oauth/authorize') {
			self._get_oauth(req, res, next);
		} else if(req.method === 'POST' && uri === '/oauth/authorize') {
			self._post_oauth(req, res, next);
		} else if(req.method === 'POST' && uri === '/oauth/access_token') {
			self._post_access_token(req, res, next);
		} else {
			next();
		}
	};
};


module.exports = OAuth2Provider;
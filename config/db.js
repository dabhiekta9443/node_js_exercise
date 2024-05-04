var mysql = require('mysql');
require('dotenv').config()
var connection = mysql.createConnection({
	host: 'localhost',
	user: 'root',
	password: 'deep70',
	database: 'node_js_exercise'
});
connection.connect(function (error) {
	if (!!error) {
		console.log(error);
		return;
	} else {
		console.log('Database Connected Successfully..!!');
	}
});

module.exports = connection;
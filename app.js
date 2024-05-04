var createError = require('http-errors');
var express = require('express');
var usersRouter = require('./routes/route');
var app = express();

// Set Port
app.set('port', (process.env.PORT || 3001));
app.listen(app.get('port'), function () {
  console.log('Server started on port ' + app.get('port'));
});

app.use(express.json());
app.use('/', usersRouter);

app.use(function (req, res, next) {
  next(createError(404));
});
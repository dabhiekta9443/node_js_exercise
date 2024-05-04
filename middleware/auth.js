var jwt = require('jsonwebtoken');
const auth = async (req, res, next) => {
    try {
        let bearerToken = req.header('Authorization');
        bearerToken = bearerToken.replace(/^Bearer\s+/, "");
        if (!bearerToken) {
            return res.status(403).json({ error: 'Please enter Bearer Token.' });
        }
        jwt.verify(bearerToken, 'radixweb8', (err, decoded) => {
            if (err) {
                return res.status(401).send({ message: "Unauthorized Token!" });
            }
            req.token = bearerToken;
            next();
        });
    } catch (e) {
        res.status(401).send({ error: 'Please enter authenticate.' })
    }
}

module.exports = auth
var express = require('express');
var router = express.Router();
var dbConn = require('../config/db');
const authBearerToken = require('../middleware/auth.js');
const bcrypt = require('bcryptjs');
var validator = require("email-validator");
const saltRounds = 10;
const { passwordStrength } = require('check-password-strength');
var jwt = require('jsonwebtoken');
const multer = require('multer');
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, './images');
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});


// Registering a New User
router.post('/api/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name && !email && !password) {
        return res.status(400).json({ error: 'Please enter name, email and password.' });
    }
    if (!name) {
        return res.status(400).json({ error: 'Please enter name.' });
    }
    if (!email) {
        return res.status(400).json({ error: 'Please enter email.' });
    }
    if (email && !validator.validate(email)) {
        return res.status(400).json({ error: "Please enter valid email." });
    }
    if (!password) {
        return res.status(400).json({ error: 'Please enter password.' });
    }
    if (password) {
        var password_error = passwordStrength(password);
        if (password.length < 8) {
            return res.status(400).json({ error: 'Please enter minimum 8 chars password.' });
        } else if (!password_error.contains.includes("lowercase") || !password_error.contains.includes("uppercase") || !password_error.contains.includes("symbol")) {
            return res.status(400).json({ error: 'Password must have one capital character, one small character & one Symbol' });
        }
    }
    try {
        const emailCheckSql = 'SELECT COUNT(*) AS count FROM user_master WHERE email = ?';
        dbConn.query(emailCheckSql, [email], async (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            const emailExists = rows[0].count > 0;
            if (emailExists) {
                return res.status(400).json({ error: 'User already exists.' });
            }

            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const newUser = { name, email, password: hashedPassword };
            const sql = 'INSERT INTO user_master (name, email, password) VALUES (?, ?, ?)';
            dbConn.query(sql, [newUser.name, newUser.email, newUser.password], (err, result) => {
                if (err) {
                    return res.status(500).json({ error: 'Failed to create user' });
                }
                res.status(201).json({ success: true, message: 'User has been created successfully.' });
            });
        });

    } catch (error) {
        res.status(500).json({ error: 'Failed to create user' });
    }

});

// Logging in
router.post('/api/auth/login', function (req, res, next) {
    try {
        var email = req.body.email;
        var password = req.body.password;

        if (!email && !password) {
            return res.status(404).json({ error: 'Please enter email and password.' });
        }
        if (email && !validator.validate(email)) {
            return res.status(400).json({ error: "Please enter valid email." });
        }
        if (!password) {
            return res.status(400).json({ error: 'Please enter password.' });
        }

        const sql = 'SELECT userid, name, email, password FROM user_master WHERE email = ?';
        dbConn.query(sql, [email], async (error, rows) => {
            const user = rows[0];
            if (user) {
                const match = await bcrypt.compare(password, user.password);
                if (!match) {
                    return res.status(401).json({ error: 'Invalid password' });
                }
                var token = jwt.sign({
                    data: email
                }, 'radixweb8', { expiresIn: 60 * 60 });
                return res.status(200).json({ success: true, message: "User has been login successfully.", token: token });
            } else {
                return res.status(404).json({ error: 'Invalid username. User not exists' });
            }
        });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

// Retrieving a List of Products
router.get('/api/products', authBearerToken, async (req, res) => {
    try {
        const keyword = req.body.keyword;
        var sql_keyword = '';
        // if(keyword) {
        //     var sql_keyword = ' WHERE (product_name LIKE "%' + keyword + '% OR product_description LIKE "%' + keyword + '%)';
        // }
        const sql = 'SELECT product_id as id, product_name, product_price, product_description, IF(product_type = "0", "Print Product", "Promotional Product") as product_type, product_image FROM products' + sql_keyword;
        // return res.json(sql);
        dbConn.query(sql, function (err, rows) {
            if (err) {
                return res.status(500).json({ error: err.message });
            } else {
                if (rows.length === 0) {
                    return res.status(404).json({ error: 'No records found.' });
                }
                return res.status(200).json({ success: true, products: rows });
            }
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Retrieving a Specific Product
router.get('/api/products/:id', authBearerToken, (req, res) => {
    try {
        const productId = req.params.id;
        const sql = 'SELECT product_id as id, product_name, product_price, product_description, IF(product_type = "0", "Print Product", "Promotional Product") as product_type, product_image FROM products WHERE product_id = ?';
        dbConn.query(sql, [productId], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            } else {
                if (rows.length === 0) {
                    return res.status(404).json({ error: 'Product not found.' });
                }
                return res.status(200).json({ success: true, product: rows });
            }
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Creating a New Product
router.post('/api/products', authBearerToken, async (req, res) => {
    try {
        const { product_name, product_price, product_description, product_type, product_image } = req.body;
        if (!product_name) {
            return res.status(400).json({ error: 'Please enter product name.' });
        }
        if (!product_price) {
            return res.status(400).json({ error: 'Please enter product price.' });
        }
        if (!product_type) {
            return res.status(400).json({ error: 'Please enter product type.' });
        }
        if (product_name) {
            var product_name_error = passwordStrength(product_name);
            if (product_name_error.contains.includes("symbol")) {
                return res.status(400).json({ error: 'Product name must be an alphanumeric string.' });
            }
        }
        if (product_price) {
            var price_pattern = /^[-+]?[0-9]+\.[0-9]+$/;
            if (!product_price.match(price_pattern)) {
                return res.status(400).json({ error: 'Product price must be decimal.' });
            }
        }
        if (product_description) {
            var product_description_error = passwordStrength(product_description);
            if (product_description_error.length > 255) {
                return res.status(400).json({ error: 'Product description should not be more than 255 Chars.' });
            }
        }
        if (product_type && product_type.toLowerCase() != 'print product' && product_type.toLowerCase() != 'promotional product') {
            return res.status(400).json({ error: 'Please type must be print product or promotional product.' });
        }
        const productType = (product_type.toLowerCase() == 'print product') ? '0' : '1';
        // exports.uploadImg = multer({ storage: storage }).single('product_image');
        // if (product_image) {

        // }

        const sql = 'INSERT INTO products (product_name, product_price, product_description, product_type, product_image) VALUES (?, ?, ?, ?, ?)';
        dbConn.query(sql, [product_name, product_price, product_description, productType, product_image], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to create product' });
            }
            res.status(200).json({ success: true, message: 'Product has been created successfully.' });
        });

    } catch (error) {
        res.status(500).json({ error: 'Failed to create product' });
    }

});

// Updating an Existing Product
router.put('/api/products/:id', authBearerToken, (req, res) => {
    try {
        const productId = req.params.id;
        const { product_name, product_price, product_description, product_type, product_image } = req.body;
        if (product_name) {
            var product_name_error = passwordStrength(product_name);
            if (product_name_error.contains.includes("symbol")) {
                return res.status(400).json({ error: 'Product name must be an alphanumeric string.' });
            }
        }
        if (product_price) {
            var price_pattern = /^[-+]?[0-9]+\.[0-9]+$/;
            if (!product_price.match(price_pattern)) {
                return res.status(400).json({ error: 'Product price must be decimal.' });
            }
        }
        if (product_description) {
            var product_description_error = passwordStrength(product_description);
            if (product_description_error.length > 255) {
                return res.status(400).json({ error: 'Product description should not be more than 255 Chars.' });
            }
        }
        if (product_type && product_type.toLowerCase() != 'print product' && product_type.toLowerCase() != 'promotional product') {
            return res.status(400).json({ error: 'Please type must be print product or promotional product.' });
        }
        const productType = (product_type.toLowerCase() == 'print product') ? '0' : '1';
        const sql = 'UPDATE products SET product_name = ?, product_price = ?, product_description = ?, product_type = ?, product_image = ? WHERE product_id = ?';
        dbConn.query(sql, [product_name, product_price, product_description, productType, product_image, productId], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to updating product', err: err });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Product not found' });
            }
            res.status(200).json({ success: true, message: 'Product has been updated successfully.' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update product' });
    }
});

// Deleting a Product
router.delete('/api/product/:id', authBearerToken, (req, res) => {
    try {
        const productId = req.params.id;
        const sql = 'DELETE FROM products WHERE product_id = ?';
        dbConn.query(sql, [productId], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to delete product' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Product not found.' });
            }
            return res.status(200).json({ success: true, message: 'Product has been deleted successfully.' });
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Product Image Upload
router.get('/api/product/images/:id', authBearerToken, (req, res) => {
    try {
        const productId = req.params.id;
        const sql = 'SELECT product_id as id, product_image FROM products WHERE product_id = ?';
        dbConn.query(sql, [productId], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            } else {
                if (rows.length === 0) {
                    return res.status(404).json({ error: 'Product image not found.' });
                }
                return res.status(200).json({ success: true, product: rows });
            }
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

module.exports = router;
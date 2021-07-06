const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

/**
 * @returns {ExpressRouter}
 * @param {MongooseModel} User 
 * @param {string} token_secret 
 */
module.exports = function (User, token_secret) {
    const router = express.Router();

    router.post('/register', async (req, res) => {
        const user = { ...req.body };
        const userFounded = await User.find({ email: user.email });
        if (userFounded.length > 0) {
            res.status(401).json({
                success: false,
                message: 'User already exists!'
            });
        } else {
            const hash = await bcrypt.hash(user.password, 3);
            user.password = hash;
            const newUser = new User({ ...user });
            await newUser.save();
            const accessToken = await jwt.sign({ id: newUser.id, email: newUser.email }, token_secret);
            res.status(201).json({
                success: true,
                data: {
                    accessToken
                }
            });
        }
    });

    router.get('/remember-me/:token', async (req, res) => {
        const token = req.params.token;
        let decodedToken;
        try {
            decodedToken = await jwt.verify(token, token_secret);
            res.status(200).json({ message: 'Token verified!', statusText: 'ok', success: true });
        } catch (e) {
            decodedToken = await jwt.decode(token);
            console.log(decodedToken);
            const foundedUser = await User.find({ email: decodedToken.email });
            if (foundedUser.length > 0) {
                const accessToken = jwt.sign({ token: foundedUser[0].refreshToken }, token_secret);
                res.status(200).json({
                    message: 'Token verified!',
                    statusText: 'ok',
                    data: { accessToken },
                    success: true
                });
            } else {
                res.status(401).json({
                    success: false,
                    message: 'User not found!',
                    statusText: 'failed'
                });
            }
        }
    });

    router.post('/login', async (req, res) => {
        const { email, password, rm } = req.body;
        const foundedUser = await User.find({ email });
        if (foundedUser.length === 0) {
            res.status(401).json({ success: false, message: 'Invalid credentials!' });
        } else {
            const [user] = foundedUser;
            const verifyStatus = await bcrypt.compare(password, user.password);
            if (!verifyStatus) {
                res.status(401).json({ success: false, message: 'Invalid credentials!' });
            } else {
                const accessToken = jwt.sign({ id: user.id, email: user.email }, token_secret);
                if (rm) {
                    const refreshToken = jwt.sign({ id: user.id, email: user.email }, token_secret);
                    user.refreshToken = refreshToken;
                    await user.save();
                }
                res.status(200).json({
                    success: true,
                    data: {
                        accessToken
                    }
                });
            }
        }
    });

    router.post('/reset-password-link', async (req, res) => {
        const { email, baseUrl } = req.body;
        const foundedUser = await User.find({ email });
        if (foundedUser.length === 0) {
            res.status(401).json({ success: false, message: 'Invalid email address!' });
        } else {
            const token = await jwt.sign({
                data: foundedUser[0].id
            }, token_secret, {
                expiresIn: 600
            });
            res.status(200).json({
                success: true,
                data: {
                    token,
                    url: baseUrl ? baseUrl + token : token,
                }
            });
        }
    });

    router.post('/change-password/:token', async (req, res) => {
        const token = req.params.token;
        const password = req.body.password;
        try {
            const id = (await jwt.verify(token, token_secret)).data;
            const hash = await bcrypt.hash(password, 3);
            console.log(id);
            const user = await User.findById(id);
            console.log(user);
            user.password = hash;
            await user.save();
            res.status(200).json({
                success: true,
                message: 'Password changed!'
            })
        } catch (e) {
            res.status(400).json({
                success: false,
                message: e.message
            })
        }

    });

    return router;
}
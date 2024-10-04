const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Message = require('./models/Message');
const User = require('./models/User');
const bcrypt = require('bcrypt');

const router = express.Router();

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        req.user = user;
        next();
    } catch (err) {
        return res.redirect('/login');
    }
};

router.get('/', (req, res) => {
    res.render('index');
});

router.get('/register', (req, res) => {
    res.render('register');
});

router.get('/send', verifyToken, (req, res) => {
    res.render('send');
});

router.post('/send', verifyToken, async (req, res) => {
    const { receiver, content } = req.body;
    const newMessage = new Message({
        sender: req.user.username,
        receiver,
        content
    });
    await newMessage.save();
    res.redirect(`/messages/${receiver}`);
});

router.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.redirect('/login');
});

router.get('/login', (req, res) => {
    res.render('login');
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).send('Usuário ou senha inválidos.');
    }
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET);
    res.cookie('token', token).redirect('/contacts');
});

router.get('/contacts', verifyToken, async (req, res) => {
    const messages = await Message.find({
        $or: [
            { sender: req.user.username },
            { receiver: req.user.username }
        ]
    });

    const contactUsernames = new Set();

    messages.forEach(message => {
        if (message.sender !== req.user.username) {
            contactUsernames.add(message.sender);
        } else {
            contactUsernames.add(message.receiver);
        }
    });

    const unreadCounts = await Promise.all(
        Array.from(contactUsernames).map(async (contactUsername) => {
            const count = await Message.countDocuments({
                receiver: req.user.username,
                sender: contactUsername,
                read: false
            });
            return { username: contactUsername, unreadCount: count };
        })
    );

    res.render('contacts', { unreadCounts });
});

router.get('/messages/:username', verifyToken, async (req, res) => {
    const messages = await Message.find({
        $or: [
            { sender: req.user.username, receiver: req.params.username },
            { sender: req.params.username, receiver: req.user.username }
        ]
    }).sort({ timestamp: 1 });

    await Message.updateMany(
        { receiver: req.user.username, sender: req.params.username, read: false },
        { $set: { read: true } }
    );

    // Passando req.user para a view
    res.render('messages', { messages, contact: req.params.username, user: req.user });
});


router.post('/messages/:username', verifyToken, async (req, res) => {
    const { content } = req.body;
    const newMessage = new Message({
        sender: req.user.username,
        receiver: req.params.username,
        content
    });
    await newMessage.save();
    res.redirect(`/messages/${req.params.username}`);
});

module.exports = router;



const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const app = express();
const Message = require('./models/Message');
const User = require('./models/User');
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/send', (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    res.render('send'); // Renderize a página de envio de mensagens
});

app.post('/send', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login'); // Verifique se o usuário está autenticado

    const user = jwt.verify(token, process.env.JWT_SECRET); // Decodifique o token para obter o usuário
    const { receiver, content } = req.body; // Suponha que você tenha um campo 'receiver' no formulário de envio

    // Crie um novo objeto de mensagem
    const newMessage = new Message({
        sender: user.username,
        receiver,
        content
    });

    // Salve a mensagem no banco de dados
    await newMessage.save();
    res.redirect(`/messages/${receiver}`); // Redirecione para a conversa com o destinatário
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).send('Usuário ou senha inválidos.');
    }
    const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET);
    res.cookie('token', token).redirect('/contacts');
});
app.get('/contacts', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    
    const user = jwt.verify(token, process.env.JWT_SECRET);
    
    const messages = await Message.find({
        $or: [
            { sender: user.username },
            { receiver: user.username }
        ]
    });

    const contactUsernames = new Set();

    messages.forEach(message => {
        if (message.sender !== user.username) {
            contactUsernames.add(message.sender);
        } else {
            contactUsernames.add(message.receiver);
        }
    });

    const unreadCounts = await Promise.all(
        Array.from(contactUsernames).map(async (contactUsername) => {
            const count = await Message.countDocuments({
                receiver: user.username,
                sender: contactUsername,
                read: false
            });
            return { username: contactUsername, unreadCount: count };
        })
    );

    res.render('contacts', { unreadCounts });
});

app.get('/messages/:username', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    const user = jwt.verify(token, process.env.JWT_SECRET);
    const messages = await Message.find({
        $or: [
            { sender: user.username, receiver: req.params.username },
            { sender: req.params.username, receiver: user.username }
        ]
    }).sort({ timestamp: 1 });

    await Message.updateMany(
        { receiver: user.username, sender: req.params.username, read: false },
        { $set: { read: true } }
    );

    res.render('messages', { messages, contact: req.params.username });
});


app.post('/messages/:username', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    const user = jwt.verify(token, process.env.JWT_SECRET);
    const { content } = req.body;
    const newMessage = new Message({
        sender: user.username,
        receiver: req.params.username,
        content
    });
    await newMessage.save();
    res.redirect(`/messages/${req.params.username}`);
});

app.listen(process.env.PORT, () => {
    console.log(`Servidor rodando na porta ${process.env.PORT}`);
});

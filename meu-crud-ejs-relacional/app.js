import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import db from './db.js';

const app = express();

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: 'pequenos-passos',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 30 * 60 * 1000
    }
}));

// Página inicial
app.get('/', (req, res) => {
    res.redirect('/login');
});

// Tela de login
app.get('/login', (req, res) => {
    res.render('login', { erro: null });
});

// Autenticação
app.post('/login', async (req, res) => {
    const { email, senha } = req.body;

    try {
        const resultado = await db.query(
            'SELECT * FROM usuarios WHERE email = $1',
            [email]
        );

        if (resultado.rows.length === 0) {
            return res.render('login', {
                erro: 'E-mail ou senha incorretos.'
            });
        }

        const usuario = resultado.rows[0];

        const senhaCorreta = await bcrypt.compare(
            senha,
            usuario.senha
        );

        if (!senhaCorreta) {
            return res.render('login', {
                erro: 'E-mail ou senha incorretos.'
            });
        }

        req.session.usuario = {
            id: usuario.id_usuario,
            nome: usuario.nome,
            email: usuario.email
        };

        res.redirect('/dashboard');

    } catch (erro) {
        console.error(erro);
        res.status(500).send('Erro ao realizar login.');
    }
});

// Dashboard
app.get('/dashboard', (req, res) => {
    if (!req.session.usuario) {
        return res.redirect('/login');
    }

    res.render('dashboard', {
        usuario: req.session.usuario
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Inicialização do servidor
app.listen(3000, () => {
    console.log('Sistema Pequenos Passos rodando em http://localhost:3000');
});
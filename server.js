const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(express.json());


let users = [];
let items = [];


const SECRET_KEY = 'rahasia-super-aman';


app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).json({ message: 'Email sudah digunakan' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: Date.now(), name, email, password: hashedPassword };
  users.push(newUser);

  res.json({ message: 'Registrasi berhasil' });
});


app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  if (!user) return res.status(400).json({ message: 'Email tidak ditemukan' });

  const validPass = await bcrypt.compare(password, user.password);
  if (!validPass) return res.status(400).json({ message: 'Password salah' });

  const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});


function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Token tidak ditemukan' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Token tidak valid' });
  }
}


app.get('/api/items', verifyToken, (req, res) => {
  res.json(items);
});


app.post('/api/items', verifyToken, (req, res) => {
  const { title, description } = req.body;
  const newItem = { id: Date.now(), title, description };
  items.push(newItem);
  res.json({ message: 'Item ditambahkan', item: newItem });
});


app.put('/api/items/:id', verifyToken, (req, res) => {
  const id = parseInt(req.params.id);
  const { title, description } = req.body;
  items = items.map(item => item.id === id ? { id, title, description } : item);
  res.json({ message: 'Item diperbarui' });
});


app.delete('/api/items/:id', verifyToken, (req, res) => {
  const id = parseInt(req.params.id);
  items = items.filter(item => item.id !== id);
  res.json({ message: 'Item dihapus' });
});


app.listen(5000, () => console.log('Backend berjalan di http://localhost:5000'));

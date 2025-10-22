const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../database"); // PostgreSQL
const { sendVerificationEmail } = require("../utils/mailer");
const { OAuth2Client } = require("google-auth-library");
require("dotenv").config();

const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ===== Cadastro =====
router.post("/register", async (req, res) => {
  const { name, email, password, photo } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "Preencha todos os campos." });

  try {
    const { rows } = await db.query("SELECT * FROM users WHERE email=$1", [email]);
    if (rows.length > 0) return res.status(400).json({ error: "E-mail já cadastrado." });

    const hash = bcrypt.hashSync(password, 10);
    const code = Math.floor(1000000 + Math.random() * 9000000).toString();
    const expires = Date.now() + 15 * 60 * 1000;

    const result = await db.query(
      `INSERT INTO users (name,email,password,photo,verification_code,verification_expires,verified)
       VALUES ($1,$2,$3,$4,$5,$6,false) RETURNING id`,
      [name, email, hash, photo || null, code, expires]
    );

    await sendVerificationEmail(email, code);
    res.json({ success: true, userId: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

// ===== Login normal =====
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Preencha todos os campos." });

  try {
    const { rows } = await db.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "Usuário não encontrado." });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: "Senha incorreta." });

    if (!user.verified) {
      const now = Date.now();
      let code = user.verification_code;
      let expires = user.verification_expires;

      if (!code || !expires || now > expires) {
        code = Math.floor(1000000 + Math.random() * 9000000).toString();
        expires = now + 15 * 60 * 1000;
        await db.query("UPDATE users SET verification_code=$1, verification_expires=$2 WHERE id=$3", [code, expires, user.id]);
      }

      await sendVerificationEmail(email, code);
      return res.json({ verify: true, message: "Verifique seu email." });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, photo: user.photo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

// ===== Login via Google =====
router.post("/google", async (req, res) => {
  const { tokenId } = req.body;
  if (!tokenId) return res.status(400).json({ error: "Token do Google é obrigatório." });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: tokenId,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { email, name, picture } = payload;

    let { rows } = await db.query("SELECT * FROM users WHERE email=$1", [email]);
    let user = rows[0];

    if (!user) {
      const result = await db.query(
        `INSERT INTO users (name, email, password, photo, verified) 
         VALUES ($1, $2, $3, $4, true) RETURNING *`,
        [name, email, "GOOGLE_AUTH", picture]
      );
      user = result.rows[0];
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, photo: user.photo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao autenticar com Google." });
  }
});

// ===== Verificação de email =====
router.post("/verify", async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: "Email e código obrigatórios." });

  try {
    const { rows } = await db.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "Usuário não encontrado." });
    if (user.verified) return res.json({ success: true, message: "Já verificado." });
    if (user.verification_code !== code) return res.status(400).json({ error: "Código incorreto." });
    if (Date.now() > user.verification_expires) return res.status(400).json({ error: "Código expirado." });

    await db.query("UPDATE users SET verified=true WHERE email=$1", [email]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

// ===== Buscar perfil =====
router.get("/profile", async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: "Email é obrigatório." });

  try {
    const { rows } = await db.query("SELECT id,name,email,photo FROM users WHERE email=$1", [email]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: "Usuário não encontrado." });
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

module.exports = router;

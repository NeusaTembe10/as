import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pool from "../database";
import { sendVerificationEmail } from "../utils/mailer";
import fetch from "node-fetch";

const router = express.Router();

// Cadastro
router.post("/register", async (req, res) => {
  const { name, email, password, photo } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "Preencha todos os campos." });

  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (rows.length) return res.status(400).json({ error: "E-mail já cadastrado." });

    const hash = bcrypt.hashSync(password, 10);
    const code = Math.floor(1000000 + Math.random() * 9000000).toString();
    const expires = Date.now() + 15 * 60 * 1000;

    const result = await pool.query(
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

// Login normal
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Preencha todos os campos." });

  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: "Usuário não encontrado." });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: "Senha incorreta." });

    if (!user.verified) {
      return res.json({ verify: true, message: "Verifique seu email." });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, photo: user.photo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro no servidor." });
  }
});

// Login Google OAuth
router.post("/google", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "Código é obrigatório." });

  try {
    // Troca código por token no Google
    const params = new URLSearchParams();
    params.append("client_id", "64491740238-adhb7tiv1rreaetehnvdi5qpk4sskd93.apps.googleusercontent.com");
    params.append("client_secret", "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");
    params.append("code", code);
    params.append("grant_type", "authorization_code");
    params.append("redirect_uri","http://localhost:1173/auth/callback");

    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      body: params,
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.status(400).json({ error: "Erro ao autenticar Google." });

    // Busca info do usuário
    const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const userData = await userRes.json();

    // Checa se já existe no DB
    let { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [userData.email]);
    let user = rows[0];

    if (!user) {
      // Cria usuário se não existir
      const result = await pool.query(
        `INSERT INTO users (name,email,photo,verified)
         VALUES ($1,$2,$3,true) RETURNING *`,
        [userData.name, userData.email, userData.picture]
      );
      user = result.rows[0];
    }

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, photo: user.photo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro no login Google." });
  }
});




// Verificação de email
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

// // Buscar perfil
// router.get("/profile", async (req, res) => {
//   const { email } = req.query;
//   if (!email) return res.status(400).json({ error: "Email é obrigatório." });

//   try {
//     const { rows } = await db.query("SELECT id,name,email,photo FROM users WHERE email=$1", [email]);
//     const user = rows[0];
//     if (!user) return res.status(404).json({ error: "Usuário não encontrado." });
//     res.json(user);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Erro no servidor." });
//   }
// });

// // Buscar usuários
// router.get("/users", async (req, res) => {
//   try {
//     const { rows } = await db.query("SELECT id,name,email,photo FROM users");
//     res.json(rows);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Erro no servidor." });
//   }
// });

// // Buscar usuários
// router.get("/users/:id", async (req, res) => {
//   const { id } = req.params;
//   try {
//     const { rows } = await db.query("SELECT id,name,email,photo FROM users WHERE id=$1", [id]);
//     const user = rows[0];
//     if (!user) return res.status(404).json({ error: "Usuário não encontrado." });
//     res.json(user);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Erro no servidor." });
//   }
// });

// // Buscar usuários
// router.get("/users/:id/verify", async (req, res) => {
//   const { id } = req.params;
//   try {
//     const { rows } = await db.query("SELECT id,name,email,photo,verified FROM users WHERE id=$1", [id]);
//     const user = rows[0];
//     if (!user) return res.status(404).json({ error: "Usuário não encontrado." });
//     res.json(user);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Erro no servidor." });
//   }
// });

 module.exports = router;

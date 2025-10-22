const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../database");
const { sendVerificationEmail } = require("../utils/mailer");
require("dotenv").config({ path: "../.env" });

const router = express.Router();

// 📌 Cadastro de usuário
router.post("/register", async (req, res) => {
  const { name, email, password, photo } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "Preencha todos os campos." });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.status(500).json({ error: "Erro no servidor." });
    if (user) {
      return res.status(400).json({ error: "E-mail já cadastrado." });
    }

    const hash = bcrypt.hashSync(password, 10);
    const code = Math.floor(1000000 + Math.random() * 9000000).toString(); // 7 dígitos
    const expires = Date.now() + 15 * 60 * 1000;

    db.run(
      "INSERT INTO users (name, email, password, photo, verification_code, verification_expires, verified) VALUES (?, ?, ?, ?, ?, ?, 0)",
      [name, email, hash, photo || null, code, expires],
      function (err) {
        if (err) return res.status(500).json({ error: "Erro ao cadastrar." });

        sendVerificationEmail(email, code)
          .then(() => res.json({ success: true, userId: this.lastID }))
          .catch(() =>
            res.status(500).json({ error: "Erro ao enviar e-mail de verificação." })
          );
      }
    );
  });
});

// 📌 Atualizar foto do perfil
router.put("/profile/photo", (req, res) => {
  const { email, photo } = req.body;

  if (!email || !photo) {
    return res.status(400).json({ error: "Email e foto são obrigatórios." });
  }

  db.run(
    "UPDATE users SET photo = ? WHERE email = ?",
    [photo, email],
    function (err) {
      if (err) return res.status(500).json({ error: "Erro ao atualizar foto." });
      res.json({ success: true });
    }
  );
});

// 📌 Login
router.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Preencha todos os campos." });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.status(500).json({ error: "Erro no servidor." });
    if (!user) {
      return res.status(400).json({ error: "Usuário não encontrado." });
    }

    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(400).json({ error: "Senha incorreta." });
    }

    if (!user.verified) {
      // Gera novo código se expirou ou não existe
      const now = Date.now();
      let code = user.verification_code;
      let expires = user.verification_expires;

      if (!code || !expires || now > expires) {
        code = Math.floor(1000000 + Math.random() * 9000000).toString(); // 7 dígitos
        expires = now + 15 * 60 * 1000;
        db.run(
          "UPDATE users SET verification_code = ?, verification_expires = ? WHERE id = ?",
          [code, expires, user.id]
        );
      }

      sendVerificationEmail(email, code)
        .then(() => res.json({ verify: true, message: "Verifique seu e-mail." }))
        .catch(() => res.status(500).json({ error: "Erro ao reenviar código." }));

      return;
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        photo: user.photo,
      },
    });
  });
});

// 📌 Verificação de e-mail
router.post("/verify", (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: "Email e código obrigatórios." });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.status(500).json({ error: "Erro no servidor." });
    if (!user) return res.status(400).json({ error: "Usuário não encontrado." });

    if (user.verified)
      return res.json({ success: true, message: "Usuário já verificado." });

    if (user.verification_code !== code)
      return res.status(400).json({ error: "Código incorreto." });

    if (Date.now() > user.verification_expires)
      return res.status(400).json({ error: "Código expirado." });

    db.run("UPDATE users SET verified = 1 WHERE email = ?", [email], (err) => {
      if (err) return res.status(500).json({ error: "Erro ao verificar usuário." });
      res.json({ success: true, message: "E-mail verificado com sucesso." });
    });
  });
});

// 📌 Buscar perfil
router.get("/profile", (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: "Email é obrigatório." });
  }

  db.get(
    "SELECT id, name, email, photo FROM users WHERE email = ?",
    [email],
    (err, user) => {
      if (err || !user)
        return res.status(404).json({ error: "Usuário não encontrado." });
      res.json(user);
    }
  );
});

module.exports = router;

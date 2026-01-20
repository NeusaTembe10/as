const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const pool = require("../database");
require("dotenv").config();

const router = express.Router();

// Middleware para verificar token JWT
function verificarToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token não fornecido." });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "chave_secreta"
    );
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido ou expirado." });
  }
}

// Login tradicional do admin
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Preencha todos os campos." });
  }

  try {
    const result = await pool.query(
      "SELECT id, username, password, type FROM admins WHERE username = $1",
      [username]
    );

    const admin = result.rows[0];

    if (!admin) {
      return res.status(400).json({ error: "Administrador não encontrado." });
    }

    // Se a senha for "google_oauth", não compare
    if (admin.password !== "google_oauth") {
      if (!bcrypt.compareSync(password, admin.password)) {
        return res.status(400).json({ error: "Senha incorreta." });
      }
    } else {
      return res
        .status(400)
        .json({ error: "Este usuário usa login com Google." });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, type: admin.type },
      process.env.JWT_SECRET || "chave_secreta",
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token,
      id: admin.id,
      username: admin.username,
      type: admin.type,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao autenticar." });
  }
});

// Buscar perfil do admin (requer autenticação)
router.get("/profile", verificarToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, username, email, type FROM admins WHERE id = $1",
      [req.admin.id]
    );

    const admin = result.rows[0];

    if (!admin) {
      return res.status(404).json({ error: "Administrador não encontrado." });
    }

    res.json(admin);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar perfil." });
  }
});

// Buscar categorias (público)
router.get("/categories", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM categories");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar categorias." });
  }
});

// ========== GOOGLE OAUTH ==========

// Gera URL de login do Google
router.get("/google/auth-url", (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = `${process.env.API_URL || "http://localhost:5000"}/api/admin/google/callback`;
  const scope = "openid email profile";

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}`;

  res.json({ authUrl });
});

// Callback do Google OAuth
router.post("/google/callback", async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ error: "Código não fornecido." });
  }

  try {
    // Troca o code por access_token
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${process.env.API_URL || "http://localhost:5000"}/api/admin/google/callback`,
        grant_type: "authorization_code",
      }
    );

    const { access_token } = tokenResponse.data;

    // Busca dados do usuário
    const userResponse = await axios.get(
      "https://www.googleapis.com/oauth2/v1/userinfo",
      {
        headers: { Authorization: `Bearer ${access_token}` },
      }
    );

    const googleUser = userResponse.data;

    // Procura admin no banco
    let result = await pool.query("SELECT * FROM admins WHERE email = $1", [
      googleUser.email,
    ]);

    let admin = result.rows[0];

    if (!admin) {
      // Cria novo admin com dados do Google
      const createResult = await pool.query(
        "INSERT INTO admins (username, email, password, type) VALUES ($1, $2, $3, $4) RETURNING id, username, email, type",
        [googleUser.name, googleUser.email, "google_oauth", "admin"]
      );
      admin = createResult.rows[0];
    }

    // Gera JWT
    const token = jwt.sign(
      {
        id: admin.id,
        username: admin.username,
        email: admin.email,
        type: admin.type,
      },
      process.env.JWT_SECRET || "chave_secreta",
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token,
      id: admin.id,
      username: admin.username,
      email: admin.email,
      type: admin.type,
    });
  } catch (err) {
    console.error("Erro no Google OAuth:", err.message);
    res
      .status(500)
      .json({ error: "Erro ao autenticar com Google.", details: err.message });
  }
});

module.exports = router;

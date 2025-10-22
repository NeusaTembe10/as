const express = require("express");
const db = require("../database");
const router = express.Router();

// Login do admin
router.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Preencha todos os campos." });
  }
  db.get("SELECT * FROM admin WHERE username = ?", [username], (err, admin) => {
    if (!admin) {
      return res.status(400).json({ error: "Administrador não encontrado." });
    }
    if (admin.password !== password) {
      return res.status(400).json({ error: "Senha incorreta." });
    }
    // Retorna dados do admin logado
    res.json({
      id: admin.id,
      username: admin.username,
      type: "admin",
    });
  });
});

// Buscar perfil do admin
router.get("/profile", (req, res) => {
  const { username } = req.query;
  if (!username) {
    return res.status(400).json({ error: "Usuário é obrigatório." });
  }
  db.get(
    "SELECT id, username FROM admin WHERE username = ?",
    [username],
    (err, admin) => {
      if (err || !admin) {
        return res.status(404).json({ error: "Administrador não encontrado." });
      }
      res.json(admin);
    }
  );
});

// Buscar categorias
router.get("/categories", (req, res) => {
  db.all("SELECT * FROM categories", (err, categories) => {
    if (err) {
      return res.status(500).json({ error: "Erro ao buscar categorias." });
    }
    res.json(categories);
  });
});


module.exports = router;

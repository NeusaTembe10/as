const express = require("express");
const multer = require("multer");
const path = require("path");
const db = require("../database");
const router = express.Router();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, path.join(__dirname, "../../public/uploads"));
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// Upload de arquivo
router.post("/upload", upload.single("file"), (req, res) => {
  const { type } = req.body;
  if (!req.file || !type) {
    return res.status(400).json({ error: "Arquivo e tipo são obrigatórios." });
  }
  // Salva no banco
  db.run(
    "INSERT INTO categories (type, name) VALUES (?, ?)",
    [type, req.file.filename],
    function (err) {
      if (err)
        return res.status(500).json({ error: "Erro ao salvar no banco." });
      res.json({ success: true, filename: req.file.filename });
    }
  );
});

// Listar arquivos por tipo
router.get("/list", (req, res) => {
  const { type } = req.query;
  db.all("SELECT * FROM categories WHERE type = ?", [type], (err, rows) => {
    if (err) return res.status(500).json({ error: "Erro ao buscar arquivos." });
    res.json(rows);
  });
});

module.exports = router;

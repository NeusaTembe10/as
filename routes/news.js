const express = require("express");
const router = express.Router();

let currentNews = {
  content: "",
  date: null,
};

// GET: retorna a novidade atual
router.get("/", (req, res) => {
  res.json(currentNews);
});

// POST: publica uma novidade
router.post("/", (req, res) => {
  const { content } = req.body;
  if (!content || typeof content !== "string") {
    return res.status(400).json({ error: "Conteúdo obrigatório" });
  }
  currentNews = {
    content,
    date: new Date().toISOString(),
  };
  res.json({ success: true, news: currentNews });
});

module.exports = router;

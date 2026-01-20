const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config();

const authRoutes = require("./routes/auth");
const adminRoutes = require("./routes/admin");
const newsRoutes = require("./routes/news");
const pool = require("./database");

const app = express();

// CORS
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://associacaosalvacao-m1be.vercel.app/",
    ],
    credentials: true,
  })
);

app.use(bodyParser.json());

// Verificar variáveis de ambiente
app.get("/api/health", (req, res) => {
  res.json({
    status: "online",
    hasGoogleConfig: !!process.env.GOOGLE_CLIENT_ID,
    hasJWTSecret: !!process.env.JWT_SECRET,
    apiUrl: process.env.API_URL,
  });
});

// Rotas
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/news", newsRoutes);

// Teste de conexão
app.get("/api/test-connection", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() as current_time");
    res.json({
      success: true,
      message: "Conectado ao banco com sucesso!",
      time: result.rows[0].current_time,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message,
    });
  }
});

app.get("/", (req, res) => {
  res.json({ message: "API online!" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

module.exports = app;

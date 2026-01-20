const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Criação das tabelas
const createTables = async () => {
  try {
    // Tabela de Usuários
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        photo TEXT,
        verified BOOLEAN DEFAULT FALSE,
        verification_code VARCHAR(10),
        verification_expires BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de Admins
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE,
        password VARCHAR(255) NOT NULL,
        type VARCHAR(50) DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de Categorias
    await pool.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        type VARCHAR(50),
        name VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de Notícias
    await pool.query(`
      CREATE TABLE IF NOT EXISTS news (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT NOT NULL,
        author VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Insere admin padrão se não existir
    const adminCheck = await pool.query(
      `SELECT * FROM admins WHERE username = $1`,
      ["admin"]
    );

    if (adminCheck.rows.length === 0) {
      const bcrypt = require("bcryptjs");
      const hashedPassword = bcrypt.hashSync("admin123", 10);

      await pool.query(
        `INSERT INTO admins (username, email, password, type) VALUES ($1, $2, $3, $4)`,
        ["admin", "admin@igreja.com", hashedPassword, "admin"]
      );

      console.log("✅ Admin padrão criado!");
    }

    console.log("✅ Tabelas criadas com sucesso!");
  } catch (err) {
    console.error("❌ Erro ao criar tabelas:", err.message);
  }
};

// Executa a criação das tabelas ao iniciar
createTables();

// Testa a conexão
pool.on("error", (err) => {
  console.error("❌ Erro na pool de conexão:", err);
});

module.exports = pool;

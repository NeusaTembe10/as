const { Pool } = require("pg");
require("dotenv").config();

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Criação das tabelas
const createTables = async () => {
  try {
    // Usuários
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        photo TEXT,
        verified BOOLEAN DEFAULT FALSE,
        verification_code VARCHAR(10),
        verification_expires BIGINT
      )
    `);

    // Admin
    await db.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE,
        password VARCHAR(255)
      )
    `);

    // Categorias
    await db.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        type VARCHAR(50),
        name VARCHAR(100)
      )
    `);

    // Insere admin padrão se não existir
    const result = await db.query(`SELECT * FROM admin WHERE username = $1`, ["ADMin"]);
    if (result.rows.length === 0) {
      await db.query(`INSERT INTO admin (username, password) VALUES ($1, $2)`, ["ADMin", "1A5S8"]);
    }

    console.log("Tabelas criadas com sucesso!");
  } catch (err) {
    console.error("Erro ao criar tabelas:", err);
  }
};

// Executa a criação das tabelas ao iniciar
createTables();

module.exports = db;
 
const Database = require("better-sqlite3");
const db = new Database("database.db");
module.exports = db;

db.exec("PRAGMA foreign_keys = ON");

db.serialize(() => {
  // Tabela de usuários
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    photo TEXT,
    verified INTEGER DEFAULT 0,
    verification_code TEXT,
    verification_expires INTEGER
  )`);

  // Tabela de admin
  db.run(`CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  // Tabela de categorias
  db.run(`CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    name TEXT
  )`);

  // Insere admin padrão se não existir
  db.get("SELECT * FROM admin WHERE username = ?", ["ADMin"], (err, row) => {
    if (!row) {
      db.run("INSERT INTO admin (username, password) VALUES (?, ?)", [
        "ADMin",
        "1A5S8",
      ]);
    }
  });
});

module.exports = db;

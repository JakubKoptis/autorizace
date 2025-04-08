const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const db = require("./db");
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "../public")));
app.use(session({
  secret: "tajnyklic",
  resave: false,
  saveUninitialized: false
}));

// === REGISTRACE ===
app.post("/register", async (req, res) => {
  const { username, name, email, password } = req.body;
  if (!username || !name || !email || !password) {
    return res.status(400).send("Vyplň všechna pole.");
  }

  const hash = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, name, email, password) VALUES (?, ?, ?, ?)",
    [username, name, email, hash],
    function (err) {
      if (err) return res.status(400).send("Chyba: uživatel nebo email už existuje.");
      req.session.userId = this.lastID;
      res.redirect("/profile.html");
    });
});

// === PŘIHLÁŠENÍ ===
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send("Špatné přihlašovací údaje.");
    }
    req.session.userId = user.id;
    res.redirect("/profile.html");
  });
});

// === ZÍSKÁNÍ AKTUÁLNÍHO UŽIVATELE ===
app.get("/me", (req, res) => {
  if (!req.session.userId) return res.status(401).send("Nepřihlášen.");
  db.get("SELECT id, username, name, email FROM users WHERE id = ?", [req.session.userId], (err, user) => {
    res.json(user);
  });
});

// === ÚPRAVA PROFILU ===
app.post("/update", (req, res) => {
  if (!req.session.userId) return res.status(401).send("Nepřihlášen.");
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).send("Vyplň všechna pole.");
  db.run("UPDATE users SET name = ?, email = ? WHERE id = ?",
    [name, email, req.session.userId],
    function (err) {
      if (err) return res.status(500).send("Chyba při aktualizaci.");
      res.redirect("/profile.html");
    });
});

// === SERVER START ===
app.listen(PORT, () => {
  console.log(`Server běží na http://localhost:${PORT}`);
});

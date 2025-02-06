const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./merchants.db");

db.run("CREATE TABLE IF NOT EXISTS merchants (id INTEGER PRIMARY KEY, email TEXT, password TEXT, apiKey TEXT)");

// Signup API
app.post("/api/signup", (req, res) => {
    const { email, password } = req.body;
    const apiKey = "API" + Math.random().toString(36).substr(2, 8);

    db.run("INSERT INTO merchants (email, password, apiKey) VALUES (?, ?, ?)", 
        [email, password, apiKey],
        function (err) {
            if (err) return res.json({ error: err.message });
            res.json({ message: "Merchant Registered!" });
        }
    );
});

// Login API
app.post("/api/login", (req, res) => {
    const { email, password } = req.body;

    db.get("SELECT * FROM merchants WHERE email = ? AND password = ?", [email, password], (err, row) => {
        if (err || !row) return res.json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: row.id }, "secret", { expiresIn: "1h" });
        res.json({ token });
    });
});

// Get API Key
app.get("/api/getApiKey", (req, res) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.sendStatus(403);

    jwt.verify(token, "secret", (err, decoded) => {
        if (err) return res.sendStatus(403);

        db.get("SELECT apiKey FROM merchants WHERE id = ?", [decoded.id], (err, row) => {
            if (err || !row) return res.sendStatus(403);
            res.json({ apiKey: row.apiKey });
        });
    });
});

app.listen(3000, () => console.log("Server running on port 3000"));


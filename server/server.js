const express = require("express");
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files (CSS, JS, images)
app.use(express.static(path.join(__dirname, "../client")));

// ----------------------
// Routes
// ----------------------

// Login Page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../client/login.html"));
});

// Login Request
app.post("/login", (req, res) => {

    const { username, password } = req.body;

    // Temporary login
    if (username === "admin" && password === "1234") {
        return res.redirect("/dashboard");
    }

    res.send("Invalid username or password");

});

// Dashboard
app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "../client/dashboard.html"));
});

// Transfer
app.post("/transfer", (req, res) => {

    const { recipient, amount, description } = req.body;

    console.log("Transfer Request:");
    console.log("Recipient:", recipient);
    console.log("Amount:", amount);
    console.log("Description:", description);

    // MongoDB will be added later

    res.send("Transfer Successful!");

});

// Logout
app.get("/logout", (req, res) => {
    res.redirect("/");
});

// ----------------------

app.listen(PORT, () => {
    console.log(`✅ SafeBank Server Running`);
    console.log(`http://localhost:${PORT}`);
});
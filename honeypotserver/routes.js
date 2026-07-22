const express = require("express");
const path = require("path");
const { login, requireAuth, destroySession } = require("./auth");
const { getDashboardData, transferMoney } = require("./transfer");

const router = express.Router();

router.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../honeypot/login.html"));
});

router.post("/login", login);

router.get("/dashboard", requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "../honeypot/dashboard.html"));
});

router.get("/api/dashboard", requireAuth, getDashboardData);
router.post("/api/transfer", requireAuth, transferMoney);

router.get("/logout", (req, res) => {
    destroySession(req, res);
    res.redirect("/");
});

module.exports = router;

require("dotenv").config({ path: require("path").join(__dirname, "../.env") });

const express = require("express");
const path = require("path");
const routes = require("./routes");
const { connectToDatabase, closeDatabase } = require("../database/mongodb");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use((req, res, next) => {
    const attackerIp =
        req.headers["x-forwarded-for"] ||
        req.socket.remoteAddress;

    console.log("--------------------------------------------------");
    console.log(`[ASSET RECEIVED] ${req.method} ${req.originalUrl}`);
    console.log(`[ASSET SOURCE IP] ${attackerIp}`);

    res.on("finish", () => {
        console.log(
            `[ASSET RESPONSE] Status ${res.statusCode} returned to Router`
        );
    });

    next();
});
app.use(express.static(path.join(__dirname, "../client")));
app.use(routes);

app.use((error, req, res, next) => {
    console.error(error);
    if (res.headersSent) return next(error);
    const message = process.env.NODE_ENV === "production"
        ? "An unexpected error occurred"
        : error.message;
    res.status(500).json({ message });
});

async function startServer() {
    try {
        await connectToDatabase();
        app.listen(PORT, () => {
            console.log("Bank Server Running");
            console.log(`http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error("Could not start server:", error.message);
        process.exit(1);
    }
}

process.on("SIGINT", async () => {
    await closeDatabase();
    process.exit(0);
});

startServer();

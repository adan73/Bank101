require("dotenv").config({ path: require("path").join(__dirname, "../.env") });

const express = require("express");
const path = require("path");
const routes = require("./routes");
const { connectToDatabase, closeDatabase } = require("../database/mongodb");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
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

const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const {
    getDatabase,
    toObjectId,
    USERS_COLLECTION
} = require("../database/honeypotmongodb");

const sessions = new Map();
const SESSION_COOKIE = "honeypot_session";
const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;

function parseCookies(req) {
    return (req.headers.cookie || "").split(";").reduce((cookies, part) => {
        const separator = part.indexOf("=");
        if (separator === -1) return cookies;
        const key = part.slice(0, separator).trim();
        const value = decodeURIComponent(part.slice(separator + 1).trim());
        if (key) cookies[key] = value;
        return cookies;
    }, {});
}

function createSession(res, userId) {
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, {
        userId: String(userId),
        expiresAt: Date.now() + SESSION_LIFETIME_MS
    });

    res.cookie(SESSION_COOKIE, token, {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: SESSION_LIFETIME_MS
    });
}

function destroySession(req, res) {
    const token = parseCookies(req)[SESSION_COOKIE];
    if (token) sessions.delete(token);
    res.clearCookie(SESSION_COOKIE);
}

function getSession(req) {
    const token = parseCookies(req)[SESSION_COOKIE];
    const session = token ? sessions.get(token) : null;
    if (!session) return null;

    if (session.expiresAt <= Date.now()) {
        sessions.delete(token);
        return null;
    }
    return session;
}

function usernameQuery(username) {
    return {
        $or: [
            { username },
            { userName: username },
            { name: username }
        ]
    };
}

async function passwordMatches(enteredPassword, storedPassword) {
    if (typeof storedPassword !== "string") return false;

    if (/^\$2[aby]\$/.test(storedPassword)) {
        return bcrypt.compare(enteredPassword, storedPassword);
    }

    // Compatibility with the current course database if passwords are plain text.
    const entered = Buffer.from(String(enteredPassword));
    const stored = Buffer.from(String(storedPassword));
    return entered.length === stored.length && crypto.timingSafeEqual(entered, stored);
}

async function login(req, res) {
    try {
        console.log(
            `[HONEYPOT] Fake login accepted for "${req.body.username}"`
        );

        const user = await getDatabase()
            .collection(USERS_COLLECTION)
            .findOne({ username: "maya" });

        if (!user) {
            return res.redirect("/?error=No honeypot user found");
        }

        createSession(res, user._id);

        return res.redirect("/dashboard");
    } catch (error) {
        console.error(error);
        return res.redirect("/");
    }
}

async function requireAuth(req, res, next) {
    try {
        const session = getSession(req);
        if (!session) {
            if (req.path.startsWith("/api/") || req.method !== "GET") {
                return res.status(401).json({ message: "Please log in" });
            }
            return res.redirect("/");
        }

        const user = await getDatabase()
            .collection(USERS_COLLECTION)
            .findOne({ _id: toObjectId(session.userId) });

        if (!user) {
            destroySession(req, res);
            return res.status(401).json({ message: "User no longer exists" });
        }

        req.user = user;
        next();
    } catch (error) {
        next(error);
    }
}

module.exports = { login, requireAuth, destroySession };

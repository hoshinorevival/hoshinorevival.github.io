const express = require("express");
const cors = require("cors");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = 3000;

// =========================
// DATABASE
// =========================

const db = new Database("hoshino.db");

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    birth_date TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS badges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL,
    icon TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_badges (
    user_id INTEGER NOT NULL,
    badge_id INTEGER NOT NULL,
    awarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, badge_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (badge_id) REFERENCES badges(id) ON DELETE CASCADE
);
`);

// =========================
// DEFAULT BADGES
// =========================

const defaultBadges = [
    ["Owner", "The owner of Hoshino.", "👑"],
    ["Developer", "Hoshino developer.", "🛠️"],
    ["Administrator", "Hoshino administrator.", "🛡️"],
    ["Moderator", "Hoshino moderator.", "🔨"],
    ["Early Supporter", "Supported Hoshino early.", "⭐"],
    ["Beta Tester", "Participated in Hoshino beta testing.", "🎮"]
];

const insertBadge = db.prepare(`
    INSERT OR IGNORE INTO badges
    (name, description, icon)
    VALUES (?, ?, ?)
`);

for (const badge of defaultBadges) {
    insertBadge.run(...badge);
}

// =========================
// MIDDLEWARE
// =========================

app.use(express.json());

app.use(cors({
    origin: "https://hoshinorevival.github.io",
    credentials: true
}));

app.use(session({
    secret: process.env.SESSION_SECRET || "HOSHINO_LOCAL_SESSION_SECRET",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        maxAge: 1000 * 60 * 60 * 24 * 30
    }
}));

// =========================
// AUTH MIDDLEWARE
// =========================

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            error: "You must be logged in."
        });
    }

    next();
}

function requireOwner(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            error: "You must be logged in."
        });
    }

    const user = db.prepare(`
        SELECT role
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!user || user.role !== "owner") {
        return res.status(403).json({
            error: "Owner access required."
        });
    }

    next();
}

// =========================
// HOME / SERVER STATUS
// =========================

app.get("/", (req, res) => {
    res.json({
        name: "Hoshino",
        status: "online",
        message: "Hoshino API is running."
    });
});

// =========================
// REGISTER
// =========================

app.post("/api/register", async (req, res) => {
    try {
        const {
            username,
            password,
            birth_date
        } = req.body;

        if (!username || !password || !birth_date) {
            return res.status(400).json({
                error: "Username, password and birth date are required."
            });
        }

        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({
                error: "Username must be between 3 and 20 characters."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error: "Password must be at least 6 characters."
            });
        }

        const birth = new Date(birth_date);

        if (Number.isNaN(birth.getTime())) {
            return res.status(400).json({
                error: "Invalid birth date."
            });
        }

        const today = new Date();

        let age = today.getFullYear() - birth.getFullYear();

        const monthDifference =
            today.getMonth() - birth.getMonth();

        if (
            monthDifference < 0 ||
            (
                monthDifference === 0 &&
                today.getDate() < birth.getDate()
            )
        ) {
            age--;
        }

        if (age < 13) {
            return res.status(400).json({
                error: "You must be at least 13 years old to create a Hoshino account."
            });
        }

        const existing = db.prepare(`
            SELECT id
            FROM users
            WHERE username = ?
        `).get(username);

        if (existing) {
            return res.status(409).json({
                error: "Username is already taken."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = db.prepare(`
            INSERT INTO users
            (username, password_hash, birth_date, role)
            VALUES (?, ?, ?, 'user')
        `).run(
            username,
            passwordHash,
            birth_date
        );

        res.json({
            success: true,
            user: {
                id: result.lastInsertRowid,
                username,
                role: "user"
            }
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Registration failed."
        });
    }
});

// =========================
// LOGIN
// =========================

app.post("/api/login", async (req, res) => {
    try {
        const {
            username,
            password
        } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                error: "Username and password are required."
            });
        }

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE username = ?
        `).get(username);

        if (!user) {
            return res.status(401).json({
                error: "Invalid username or password."
            });
        }

        const validPassword = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!validPassword) {
            return res.status(401).json({
                error: "Invalid username or password."
            });
        }

        req.session.userId = user.id;

        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Login failed."
        });
    }
});

// =========================
// CURRENT SESSION
// =========================

app.get("/api/me", (req, res) => {
    if (!req.session.userId) {
        return res.json({
            loggedIn: false
        });
    }

    const user = db.prepare(`
        SELECT id, username, birth_date, role, created_at
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!user) {
        req.session.destroy(() => {});

        return res.json({
            loggedIn: false
        });
    }

    res.json({
        loggedIn: true,
        user
    });
});

// =========================
// LOGOUT
// =========================

app.post("/api/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error(error);

            return res.status(500).json({
                error: "Logout failed."
            });
        }

        res.clearCookie("connect.sid");

        res.json({
            success: true
        });
    });
});

// =========================
// PROFILE
// =========================

app.get("/api/profile", requireAuth, (req, res) => {
    const user = db.prepare(`
        SELECT id, username, birth_date, role, created_at
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!user) {
        return res.status(404).json({
            error: "User not found."
        });
    }

    res.json(user);
});

// =========================
// BADGES
// =========================

app.get("/api/my-badges", requireAuth, (req, res) => {
    const badges = db.prepare(`
        SELECT
            b.id,
            b.name,
            b.description,
            b.icon,
            ub.awarded_at
        FROM user_badges ub
        JOIN badges b
            ON b.id = ub.badge_id
        WHERE ub.user_id = ?
        ORDER BY ub.awarded_at ASC
    `).all(req.session.userId);

    res.json(badges);
});

app.get("/api/users/:id/badges", (req, res) => {
    const badges = db.prepare(`
        SELECT
            b.id,
            b.name,
            b.description,
            b.icon,
            ub.awarded_at
        FROM user_badges ub
        JOIN badges b
            ON b.id = ub.badge_id
        WHERE ub.user_id = ?
        ORDER BY ub.awarded_at ASC
    `).all(req.params.id);

    res.json(badges);
});

// =========================
// ADMIN / OWNER BADGE AWARD
// =========================

app.post(
    "/api/admin/users/:userId/badges",
    requireOwner,
    (req, res) => {

        const {
            badge_id
        } = req.body;

        if (!badge_id) {
            return res.status(400).json({
                error: "badge_id is required."
            });
        }

        const user = db.prepare(`
            SELECT id
            FROM users
            WHERE id = ?
        `).get(req.params.userId);

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        const badge = db.prepare(`
            SELECT id
            FROM badges
            WHERE id = ?
        `).get(badge_id);

        if (!badge) {
            return res.status(404).json({
                error: "Badge not found."
            });
        }

        db.prepare(`
            INSERT OR IGNORE INTO user_badges
            (user_id, badge_id)
            VALUES (?, ?)
        `).run(
            req.params.userId,
            badge_id
        );

        res.json({
            success: true
        });
    }
);

// =========================
// CHANGE PASSWORD
// =========================

app.post("/api/change-password", requireAuth, async (req, res) => {
    try {
        const {
            currentPassword,
            newPassword
        } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                error: "Current and new passwords are required."
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                error: "New password must be at least 6 characters."
            });
        }

        const user = db.prepare(`
            SELECT password_hash
            FROM users
            WHERE id = ?
        `).get(req.session.userId);

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        const valid = await bcrypt.compare(
            currentPassword,
            user.password_hash
        );

        if (!valid) {
            return res.status(401).json({
                error: "Current password is incorrect."
            });
        }

        const newHash = await bcrypt.hash(
            newPassword,
            12
        );

        db.prepare(`
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
        `).run(
            newHash,
            req.session.userId
        );

        res.json({
            success: true
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            error: "Password change failed."
        });
    }
});

// =========================
// STATS
// =========================

app.get("/api/my-stats", requireAuth, (req, res) => {
    const achievements = db.prepare(`
        SELECT COUNT(*) AS count
        FROM user_badges
        WHERE user_id = ?
    `).get(req.session.userId).count;

    res.json({
        gamesPlayed: 0,
        achievements
    });
});

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
    console.log(`Hoshino API running on http://localhost:${PORT}`);
});

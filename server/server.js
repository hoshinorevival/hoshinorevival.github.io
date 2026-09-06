const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT) || 3000;

const NODE_ENV = process.env.NODE_ENV || "development";

const FRONTEND_URL =
    process.env.FRONTEND_URL ||
    "http://localhost:5500,http://127.0.0.1:5500";

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    "HOSHINO_LOCAL_DEVELOPMENT_SECRET_CHANGE_ME";

const IS_PRODUCTION = NODE_ENV === "production";

/* =========================================================
   BASIC APP CONFIG
========================================================= */

app.disable("x-powered-by");

if (IS_PRODUCTION) {
    app.set("trust proxy", 1);
}

/* =========================================================
   SECURITY HEADERS
========================================================= */

app.use(
    helmet({
        crossOriginResourcePolicy: {
            policy: "cross-origin"
        }
    })
);

/* =========================================================
   CORS
========================================================= */

const allowedOrigins = FRONTEND_URL
    .split(",")
    .map(origin => origin.trim())
    .filter(Boolean);

app.use(
    cors({
        origin: function (origin, callback) {
            // Allow requests with no Origin header.
            // Useful for direct API checks/server-side requests.
            if (!origin) {
                return callback(null, true);
            }

            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            console.warn(
                `[CORS] Blocked origin: ${origin}`
            );

            return callback(
                new Error("Origin not allowed by Hoshino CORS policy.")
            );
        },

        credentials: true,

        methods: [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS"
        ],

        allowedHeaders: [
            "Content-Type",
            "Authorization"
        ]
    })
);

/* =========================================================
   BODY PARSING
========================================================= */

app.use(
    express.json({
        limit: "100kb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "100kb"
    })
);

/* =========================================================
   DATABASE
========================================================= */

const db = new Database("hoshino.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

/* =========================================================
   DATABASE TABLES
========================================================= */

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

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

        FOREIGN KEY (badge_id)
            REFERENCES badges(id)
            ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_users_username
        ON users(username);

    CREATE INDEX IF NOT EXISTS idx_user_badges_user
        ON user_badges(user_id);

    CREATE INDEX IF NOT EXISTS idx_user_badges_badge
        ON user_badges(badge_id);
`);

/* =========================================================
   DEFAULT BADGES
========================================================= */

const defaultBadges = [
    [
        "Owner",
        "The owner of Hoshino.",
        "👑"
    ],

    [
        "Developer",
        "Hoshino developer.",
        "🛠️"
    ],

    [
        "Administrator",
        "Hoshino administrator.",
        "🛡️"
    ],

    [
        "Moderator",
        "Hoshino moderator.",
        "🔨"
    ],

    [
        "Early Supporter",
        "Supported Hoshino early.",
        "⭐"
    ],

    [
        "Beta Tester",
        "Participated in Hoshino beta testing.",
        "🎮"
    ]
];

const insertBadge = db.prepare(`
    INSERT OR IGNORE INTO badges
    (
        name,
        description,
        icon
    )
    VALUES (?, ?, ?)
`);

for (const badge of defaultBadges) {
    insertBadge.run(...badge);
}

/* =========================================================
   SESSION
========================================================= */

app.use(
    session({
        name: "hoshino.sid",

        secret: SESSION_SECRET,

        resave: false,

        saveUninitialized: false,

        rolling: true,

        cookie: {
            httpOnly: true,

            secure: IS_PRODUCTION,

            sameSite: IS_PRODUCTION
                ? "none"
                : "lax",

            maxAge:
                1000 *
                60 *
                60 *
                24 *
                30
        }
    })
);

/* =========================================================
   REQUEST LOGGER
========================================================= */

app.use((req, res, next) => {
    const start = Date.now();

    res.on("finish", () => {
        const duration = Date.now() - start;

        console.log(
            `[${new Date().toISOString()}] ` +
            `${req.method} ${req.originalUrl} ` +
            `${res.statusCode} ` +
            `${duration}ms`
        );
    });

    next();
});

/* =========================================================
   HELPERS
========================================================= */

function normalizeUsername(username) {
    return String(username || "").trim();
}

function isValidUsername(username) {
    return /^[A-Za-z0-9_]{3,20}$/.test(username);
}

function isValidBirthDate(value) {
    if (typeof value !== "string") {
        return false;
    }

    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        return false;
    }

    const date = new Date(`${value}T00:00:00`);

    return !Number.isNaN(date.getTime());
}

function calculateAge(birthDate) {
    const birth = new Date(`${birthDate}T00:00:00`);
    const today = new Date();

    let age =
        today.getFullYear() -
        birth.getFullYear();

    const monthDifference =
        today.getMonth() -
        birth.getMonth();

    if (
        monthDifference < 0 ||
        (
            monthDifference === 0 &&
            today.getDate() < birth.getDate()
        )
    ) {
        age--;
    }

    return age;
}

function publicUser(user) {
    return {
        id: user.id,
        username: user.username,
        birth_date: user.birth_date,
        role: user.role,
        created_at: user.created_at
    };
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({
            success: false,
            error: "You must be logged in."
        });
    }

    next();
}

function requireOwner(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({
            success: false,
            error: "You must be logged in."
        });
    }

    const user = db.prepare(`
        SELECT id, role
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!user) {
        req.session.destroy(() => {});

        return res.status(401).json({
            success: false,
            error: "Your session is no longer valid."
        });
    }

    if (user.role !== "owner") {
        return res.status(403).json({
            success: false,
            error: "Owner access required."
        });
    }

    next();
}

/* =========================================================
   ROOT / API STATUS
========================================================= */

app.get("/", (req, res) => {
    res.status(200).json({
        name: "Hoshino",
        status: "online",
        message: "Hoshino API is running.",
        version: "1.0.0"
    });
});

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/api/health", (req, res) => {
    let databaseOnline = false;

    try {
        db.prepare("SELECT 1").get();
        databaseOnline = true;
    } catch (error) {
        console.error(
            "[HEALTH] Database error:",
            error.message
        );
    }

    const healthy = databaseOnline;

    res.status(healthy ? 200 : 503).json({
        ok: healthy,
        service: "Hoshino API",
        status: healthy
            ? "online"
            : "degraded",
        database: databaseOnline
            ? "online"
            : "offline",
        timestamp: new Date().toISOString()
    });
});

/* =========================================================
   API STATUS
========================================================= */

app.get("/api/status", (req, res) => {
    res.json({
        name: "Hoshino",
        status: "online",
        environment: NODE_ENV,
        timestamp: new Date().toISOString()
    });
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res, next) => {
    try {
        let {
            username,
            password,
            birth_date
        } = req.body;

        username = normalizeUsername(username);

        if (
            !username ||
            !password ||
            !birth_date
        ) {
            return res.status(400).json({
                success: false,
                error:
                    "Username, password and birth date are required."
            });
        }

        if (!isValidUsername(username)) {
            return res.status(400).json({
                success: false,
                error:
                    "Username must be 3-20 characters and contain only letters, numbers and underscores."
            });
        }

        if (typeof password !== "string") {
            return res.status(400).json({
                success: false,
                error: "Invalid password."
            });
        }

        if (
            password.length < 6 ||
            password.length > 128
        ) {
            return res.status(400).json({
                success: false,
                error:
                    "Password must be between 6 and 128 characters."
            });
        }

        if (!isValidBirthDate(birth_date)) {
            return res.status(400).json({
                success: false,
                error: "Invalid birth date."
            });
        }

        const age = calculateAge(birth_date);

        if (age < 13) {
            return res.status(400).json({
                success: false,
                error:
                    "You must be at least 13 years old to create a Hoshino account."
            });
        }

        const existing = db.prepare(`
            SELECT id
            FROM users
            WHERE username = ?
        `).get(username);

        if (existing) {
            return res.status(409).json({
                success: false,
                error: "Username is already taken."
            });
        }

        const passwordHash =
            await bcrypt.hash(password, 12);

        const result = db.prepare(`
            INSERT INTO users
            (
                username,
                password_hash,
                birth_date,
                role
            )
            VALUES (?, ?, ?, 'user')
        `).run(
            username,
            passwordHash,
            birth_date
        );

        const newUser = db.prepare(`
            SELECT
                id,
                username,
                birth_date,
                role,
                created_at
            FROM users
            WHERE id = ?
        `).get(result.lastInsertRowid);

        return res.status(201).json({
            success: true,
            user: publicUser(newUser)
        });

    } catch (error) {
        next(error);
    }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res, next) => {
    try {
        let {
            username,
            password
        } = req.body;

        username = normalizeUsername(username);

        if (
            !username ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                error:
                    "Username and password are required."
            });
        }

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE username = ?
        `).get(username);

        if (!user) {
            return res.status(401).json({
                success: false,
                error:
                    "Invalid username or password."
            });
        }

        const validPassword =
            await bcrypt.compare(
                password,
                user.password_hash
            );

        if (!validPassword) {
            return res.status(401).json({
                success: false,
                error:
                    "Invalid username or password."
            });
        }

        req.session.userId = user.id;

        req.session.save((error) => {
            if (error) {
                return next(error);
            }

            return res.json({
                success: true,
                user: publicUser(user)
            });
        });

    } catch (error) {
        next(error);
    }
});

/* =========================================================
   CURRENT SESSION
========================================================= */

app.get("/api/me", (req, res) => {
    if (
        !req.session ||
        !req.session.userId
    ) {
        return res.json({
            loggedIn: false,
            user: null
        });
    }

    const user = db.prepare(`
        SELECT
            id,
            username,
            birth_date,
            role,
            created_at
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!user) {
        return req.session.destroy(() => {
            res.json({
                loggedIn: false,
                user: null
            });
        });
    }

    res.json({
        loggedIn: true,
        user
    });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res, next) => {
    if (!req.session) {
        return res.json({
            success: true
        });
    }

    req.session.destroy((error) => {
        if (error) {
            return next(error);
        }

        res.clearCookie("hoshino.sid");

        res.json({
            success: true
        });
    });
});

/* =========================================================
   PROFILE
========================================================= */

app.get(
    "/api/profile",
    requireAuth,
    (req, res) => {
        const user = db.prepare(`
            SELECT
                id,
                username,
                birth_date,
                role,
                created_at
            FROM users
            WHERE id = ?
        `).get(req.session.userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: "User not found."
            });
        }

        res.json(user);
    }
);

/* =========================================================
   PUBLIC USER BADGES
========================================================= */

app.get(
    "/api/users/:id/badges",
    (req, res) => {
        const userId =
            Number(req.params.id);

        if (!Number.isInteger(userId)) {
            return res.status(400).json({
                success: false,
                error: "Invalid user ID."
            });
        }

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
        `).all(userId);

        res.json(badges);
    }
);

/* =========================================================
   MY BADGES
========================================================= */

app.get(
    "/api/my-badges",
    requireAuth,
    (req, res) => {
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
    }
);

/* =========================================================
   ALL BADGES
========================================================= */

app.get(
    "/api/badges",
    (req, res) => {
        const badges = db.prepare(`
            SELECT
                id,
                name,
                description,
                icon,
                created_at
            FROM badges
            ORDER BY id ASC
        `).all();

        res.json(badges);
    }
);

/* =========================================================
   OWNER: AWARD BADGE
========================================================= */

app.post(
    "/api/admin/users/:userId/badges",
    requireOwner,
    (req, res) => {
        const userId =
            Number(req.params.userId);

        const badgeId =
            Number(req.body.badge_id);

        if (
            !Number.isInteger(userId) ||
            !Number.isInteger(badgeId)
        ) {
            return res.status(400).json({
                success: false,
                error:
                    "Valid userId and badge_id are required."
            });
        }

        const user = db.prepare(`
            SELECT id
            FROM users
            WHERE id = ?
        `).get(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: "User not found."
            });
        }

        const badge = db.prepare(`
            SELECT id
            FROM badges
            WHERE id = ?
        `).get(badgeId);

        if (!badge) {
            return res.status(404).json({
                success: false,
                error: "Badge not found."
            });
        }

        db.prepare(`
            INSERT OR IGNORE INTO user_badges
            (
                user_id,
                badge_id
            )
            VALUES (?, ?)
        `).run(
            userId,
            badgeId
        );

        res.json({
            success: true
        });
    }
);

/* =========================================================
   OWNER: REMOVE BADGE
========================================================= */

app.delete(
    "/api/admin/users/:userId/badges/:badgeId",
    requireOwner,
    (req, res) => {
        const userId =
            Number(req.params.userId);

        const badgeId =
            Number(req.params.badgeId);

        if (
            !Number.isInteger(userId) ||
            !Number.isInteger(badgeId)
        ) {
            return res.status(400).json({
                success: false,
                error: "Invalid ID."
            });
        }

        const result = db.prepare(`
            DELETE FROM user_badges
            WHERE user_id = ?
            AND badge_id = ?
        `).run(
            userId,
            badgeId
        );

        if (result.changes === 0) {
            return res.status(404).json({
                success: false,
                error: "Badge award not found."
            });
        }

        res.json({
            success: true
        });
    }
);

/* =========================================================
   CHANGE PASSWORD
========================================================= */

app.post(
    "/api/change-password",
    requireAuth,
    async (req, res, next) => {
        try {
            const {
                currentPassword,
                newPassword
            } = req.body;

            if (
                !currentPassword ||
                !newPassword
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        "Current and new passwords are required."
                });
            }

            if (
                typeof newPassword !== "string" ||
                newPassword.length < 6 ||
                newPassword.length > 128
            ) {
                return res.status(400).json({
                    success: false,
                    error:
                        "New password must be between 6 and 128 characters."
                });
            }

            const user = db.prepare(`
                SELECT password_hash
                FROM users
                WHERE id = ?
            `).get(req.session.userId);

            if (!user) {
                return res.status(404).json({
                    success: false,
                    error: "User not found."
                });
            }

            const valid =
                await bcrypt.compare(
                    currentPassword,
                    user.password_hash
                );

            if (!valid) {
                return res.status(401).json({
                    success: false,
                    error:
                        "Current password is incorrect."
                });
            }

            const newHash =
                await bcrypt.hash(
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
            next(error);
        }
    }
);

/* =========================================================
   MY STATS
========================================================= */

app.get(
    "/api/my-stats",
    requireAuth,
    (req, res) => {
        const achievements =
            db.prepare(`
                SELECT COUNT(*) AS count
                FROM user_badges
                WHERE user_id = ?
            `).get(
                req.session.userId
            ).count;

        res.json({
            gamesPlayed: 0,
            achievements
        });
    }
);

/* =========================================================
   OWNER: USER LOOKUP
========================================================= */

app.get(
    "/api/admin/users/:id",
    requireOwner,
    (req, res) => {
        const userId =
            Number(req.params.id);

        if (!Number.isInteger(userId)) {
            return res.status(400).json({
                success: false,
                error: "Invalid user ID."
            });
        }

        const user = db.prepare(`
            SELECT
                id,
                username,
                birth_date,
                role,
                created_at
            FROM users
            WHERE id = ?
        `).get(userId);

        if (!user) {
            return res.status(404).json({
                success: false,
                error: "User not found."
            });
        }

        res.json(user);
    }
);

/* =========================================================
   API 404 HANDLER
========================================================= */

app.use("/api", (req, res) => {
    res.status(404).json({
        success: false,
        error: "Hoshino API endpoint not found."
    });
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
    console.error(
        "[HOSHINO ERROR]",
        error
    );

    if (res.headersSent) {
        return next(error);
    }

    if (
        error.message ===
        "Origin not allowed by Hoshino CORS policy."
    ) {
        return res.status(403).json({
            success: false,
            error: "Origin not allowed."
        });
    }

    res.status(500).json({
        success: false,
        error:
            "An internal Hoshino server error occurred."
    });
});

/* =========================================================
   START SERVER
========================================================= */

const server = app.listen(
    PORT,
    () => {
        console.log("");
        console.log("======================================");
        console.log("        HOSHINO API SERVER");
        console.log("======================================");
        console.log(
            `Status:       ONLINE`
        );
        console.log(
            `Environment:  ${NODE_ENV}`
        );
        console.log(
            `Port:         ${PORT}`
        );
        console.log(
            `Frontend:     ${FRONTEND_URL}`
        );
        console.log(
            `Health:       /api/health`
        );
        console.log(
            `Database:     hoshino.db`
        );
        console.log("======================================");
        console.log("");
    }
);

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

function shutdown(signal) {
    console.log(
        `\n[HOSHINO] ${signal} received.`
    );

    server.close(() => {
        console.log(
            "[HOSHINO] HTTP server closed."
        );

        try {
            db.close();

            console.log(
                "[HOSHINO] Database closed."
            );
        } catch (error) {
            console.error(
                "[HOSHINO] Database shutdown error:",
                error
            );
        }

        process.exit(0);
    });
}

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

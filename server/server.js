const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT) || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    "HOSHINO_LOCAL_DEVELOPMENT_SECRET_CHANGE_ME";

const IS_PRODUCTION = NODE_ENV === "production";

/* =========================================================
   APP
========================================================= */

if (IS_PRODUCTION) {
    app.set("trust proxy", 1);
}

app.disable("x-powered-by");

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({
    extended: false,
    limit: "100kb"
}));

/* =========================================================
   CORS
========================================================= */

app.use(
    cors({
        origin: function (origin, callback) {
            // Requests without an Origin header are allowed.
            if (!origin) {
                return callback(null, true);
            }

            // Allow ANY localhost / 127.0.0.1 port.
            const localOrigin =
                /^http:\/\/localhost(:\d+)?$/.test(origin) ||
                /^http:\/\/127\.0\.0\.1(:\d+)?$/.test(origin);

            if (localOrigin) {
                console.log(`[CORS] Allowed local origin: ${origin}`);
                return callback(null, true);
            }

            // GitHub Pages
            if (origin === "https://hoshinorevival.github.io") {
                console.log(`[CORS] Allowed Hoshino website: ${origin}`);
                return callback(null, true);
            }

            console.warn(`[CORS] Blocked origin: ${origin}`);

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
   DATABASE
========================================================= */

const db = new Database("hoshino.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

/* =========================================================
   TABLES
========================================================= */

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        birth_date TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS badges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
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
`);

/* =========================================================
   INDEXES
========================================================= */

db.exec(`
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

const insertBadge = db.prepare(`
    INSERT OR IGNORE INTO badges
        (name, description, icon)
    VALUES
        (?, ?, ?)
`);

const defaultBadges = [
    ["Owner", "The owner of Hoshino.", "👑"],
    ["Developer", "A Hoshino developer.", "🛠️"],
    ["Administrator", "A Hoshino administrator.", "🛡️"],
    ["Moderator", "A Hoshino moderator.", "🔨"],
    ["Early Supporter", "Supported Hoshino early in development.", "⭐"],
    ["Beta Tester", "Participated in Hoshino beta testing.", "🎮"]
];

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

            maxAge: 1000 * 60 * 60 * 24 * 30
        }
    })
);

/* =========================================================
   REQUEST LOGGER
========================================================= */

app.use((req, res, next) => {
    console.log(
        `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`
    );

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

function isValidBirthDate(birthDate) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(birthDate)) {
        return false;
    }

    const date = new Date(`${birthDate}T00:00:00`);

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
        role: user.role,
        birthDate: user.birth_date,
        createdAt: user.created_at
    };
}

/* =========================================================
   AUTH
========================================================= */

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

    const user = db
        .prepare(`
            SELECT id, username, role
            FROM users
            WHERE id = ?
        `)
        .get(req.session.userId);

    if (!user || user.role !== "owner") {
        return res.status(403).json({
            error: "Owner access required."
        });
    }

    next();
}

/* =========================================================
   ROOT
========================================================= */

app.get("/", (req, res) => {
    res.json({
        name: "Hoshino",
        status: "online",
        message: "Hoshino API is running."
    });
});

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
    try {
        db.prepare("SELECT 1").get();

        res.json({
            ok: true,
            service: "Hoshino API",
            status: "online",
            database: "online",
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error("[HEALTH ERROR]", error);

        res.status(500).json({
            ok: false,
            service: "Hoshino API",
            status: "online",
            database: "offline"
        });
    }
});

/* =========================================================
   STATUS
========================================================= */

app.get("/api/status", (req, res) => {
    res.json({
        name: "Hoshino",
        status: "online",
        version: "2016",
        environment: NODE_ENV
    });
});

/* =========================================================
   REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
    try {
        const username =
            normalizeUsername(req.body.username);

        const password =
            String(req.body.password || "");

        const birthDate =
            String(req.body.birthDate || "");

        if (!isValidUsername(username)) {
            return res.status(400).json({
                error:
                    "Username must be 3-20 characters and use only letters, numbers, or underscores."
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                error:
                    "Password must be at least 8 characters."
            });
        }

        if (!isValidBirthDate(birthDate)) {
            return res.status(400).json({
                error: "Invalid birth date."
            });
        }

        if (calculateAge(birthDate) < 13) {
            return res.status(400).json({
                error:
                    "You must be at least 13 years old to use Hoshino."
            });
        }

        const existing = db
            .prepare(`
                SELECT id
                FROM users
                WHERE username = ?
            `)
            .get(username);

        if (existing) {
            return res.status(409).json({
                error:
                    "That username is already taken."
            });
        }

        const passwordHash =
            await bcrypt.hash(password, 12);

        const result = db
            .prepare(`
                INSERT INTO users
                    (username, password_hash, birth_date)
                VALUES
                    (?, ?, ?)
            `)
            .run(
                username,
                passwordHash,
                birthDate
            );

        const user = db
            .prepare(`
                SELECT *
                FROM users
                WHERE id = ?
            `)
            .get(result.lastInsertRowid);

        req.session.userId = user.id;

        req.session.save(error => {
            if (error) {
                console.error(
                    "[SESSION ERROR]",
                    error
                );

                return res.status(500).json({
                    error:
                        "Could not create login session."
                });
            }

            res.status(201).json({
                message: "Account created.",
                user: publicUser(user)
            });
        });

    } catch (error) {
        console.error(
            "[REGISTER ERROR]",
            error
        );

        res.status(500).json({
            error: "Registration failed."
        });
    }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
    try {
        const username =
            normalizeUsername(req.body.username);

        const password =
            String(req.body.password || "");

        if (!username || !password) {
            return res.status(400).json({
                error:
                    "Username and password are required."
            });
        }

        const user = db
            .prepare(`
                SELECT *
                FROM users
                WHERE username = ?
            `)
            .get(username);

        if (!user) {
            return res.status(401).json({
                error:
                    "Invalid username or password."
            });
        }

        const passwordCorrect =
            await bcrypt.compare(
                password,
                user.password_hash
            );

        if (!passwordCorrect) {
            return res.status(401).json({
                error:
                    "Invalid username or password."
            });
        }

        req.session.userId = user.id;

        req.session.save(error => {
            if (error) {
                console.error(
                    "[LOGIN SESSION ERROR]",
                    error
                );

                return res.status(500).json({
                    error:
                        "Could not save login session."
                });
            }

            res.json({
                message: "Login successful.",
                user: publicUser(user)
            });
        });

    } catch (error) {
        console.error(
            "[LOGIN ERROR]",
            error
        );

        res.status(500).json({
            error: "Login failed."
        });
    }
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", (req, res) => {
    if (!req.session.userId) {
        return res.json({
            loggedIn: false,
            user: null
        });
    }

    const user = db
        .prepare(`
            SELECT *
            FROM users
            WHERE id = ?
        `)
        .get(req.session.userId);

    if (!user) {
        req.session.destroy(() => {});

        return res.json({
            loggedIn: false,
            user: null
        });
    }

    res.json({
        loggedIn: true,
        user: publicUser(user)
    });
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {
    req.session.destroy(error => {
        if (error) {
            console.error(
                "[LOGOUT ERROR]",
                error
            );

            return res.status(500).json({
                error: "Logout failed."
            });
        }

        res.clearCookie("hoshino.sid");

        res.json({
            message: "Logged out."
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
        const user = db
            .prepare(`
                SELECT *
                FROM users
                WHERE id = ?
            `)
            .get(req.session.userId);

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        res.json({
            user: publicUser(user)
        });
    }
);

/* =========================================================
   USER BADGES
========================================================= */

app.get(
    "/api/users/:id/badges",
    (req, res) => {
        const userId =
            Number(req.params.id);

        if (!Number.isInteger(userId)) {
            return res.status(400).json({
                error: "Invalid user ID."
            });
        }

        const badges = db
            .prepare(`
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
            `)
            .all(userId);

        res.json({
            badges
        });
    }
);

/* =========================================================
   MY BADGES
========================================================= */

app.get(
    "/api/my-badges",
    requireAuth,
    (req, res) => {
        const badges = db
            .prepare(`
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
            `)
            .all(req.session.userId);

        res.json({
            badges
        });
    }
);

/* =========================================================
   ALL BADGES
========================================================= */

app.get("/api/badges", (req, res) => {
    const badges = db
        .prepare(`
            SELECT
                id,
                name,
                description,
                icon,
                created_at
            FROM badges
            ORDER BY id ASC
        `)
        .all();

    res.json({
        badges
    });
});

/* =========================================================
   OWNER - AWARD BADGE
========================================================= */

app.post(
    "/api/admin/users/:userId/badges",
    requireOwner,
    (req, res) => {
        const userId =
            Number(req.params.userId);

        const badgeId =
            Number(req.body.badgeId);

        if (
            !Number.isInteger(userId) ||
            !Number.isInteger(badgeId)
        ) {
            return res.status(400).json({
                error:
                    "Invalid user or badge ID."
            });
        }

        const user = db
            .prepare(`
                SELECT id
                FROM users
                WHERE id = ?
            `)
            .get(userId);

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        const badge = db
            .prepare(`
                SELECT id
                FROM badges
                WHERE id = ?
            `)
            .get(badgeId);

        if (!badge) {
            return res.status(404).json({
                error: "Badge not found."
            });
        }

        db.prepare(`
            INSERT OR IGNORE INTO user_badges
                (user_id, badge_id)
            VALUES
                (?, ?)
        `).run(
            userId,
            badgeId
        );

        res.json({
            message: "Badge awarded."
        });
    }
);

/* =========================================================
   OWNER - REMOVE BADGE
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
                error:
                    "Invalid user or badge ID."
            });
        }

        const result = db
            .prepare(`
                DELETE FROM user_badges
                WHERE user_id = ?
                AND badge_id = ?
            `)
            .run(
                userId,
                badgeId
            );

        if (result.changes === 0) {
            return res.status(404).json({
                error:
                    "Badge was not awarded to this user."
            });
        }

        res.json({
            message: "Badge removed."
        });
    }
);

/* =========================================================
   CHANGE PASSWORD
========================================================= */

app.post(
    "/api/change-password",
    requireAuth,
    async (req, res) => {
        try {
            const currentPassword =
                String(
                    req.body.currentPassword || ""
                );

            const newPassword =
                String(
                    req.body.newPassword || ""
                );

            if (newPassword.length < 8) {
                return res.status(400).json({
                    error:
                        "New password must be at least 8 characters."
                });
            }

            const user = db
                .prepare(`
                    SELECT *
                    FROM users
                    WHERE id = ?
                `)
                .get(req.session.userId);

            if (!user) {
                return res.status(404).json({
                    error: "User not found."
                });
            }

            const correct =
                await bcrypt.compare(
                    currentPassword,
                    user.password_hash
                );

            if (!correct) {
                return res.status(401).json({
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
                user.id
            );

            res.json({
                message:
                    "Password changed successfully."
            });

        } catch (error) {
            console.error(
                "[PASSWORD ERROR]",
                error
            );

            res.status(500).json({
                error:
                    "Password change failed."
            });
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
        const user = db
            .prepare(`
                SELECT
                    id,
                    username,
                    role,
                    created_at
                FROM users
                WHERE id = ?
            `)
            .get(req.session.userId);

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        const badgeCount = db
            .prepare(`
                SELECT COUNT(*) AS count
                FROM user_badges
                WHERE user_id = ?
            `)
            .get(user.id);

        res.json({
            userId: user.id,
            username: user.username,
            role: user.role,
            accountCreated: user.created_at,
            badgeCount: badgeCount.count
        });
    }
);

/* =========================================================
   OWNER - USER LOOKUP
========================================================= */

app.get(
    "/api/admin/users/:id",
    requireOwner,
    (req, res) => {
        const userId =
            Number(req.params.id);

        if (!Number.isInteger(userId)) {
            return res.status(400).json({
                error: "Invalid user ID."
            });
        }

        const user = db
            .prepare(`
                SELECT
                    id,
                    username,
                    birth_date,
                    role,
                    created_at
                FROM users
                WHERE id = ?
            `)
            .get(userId);

        if (!user) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        res.json({
            user: publicUser(user)
        });
    }
);

/* =========================================================
   API 404
========================================================= */

app.use("/api", (req, res) => {
    res.status(404).json({
        error:
            "Hoshino API endpoint not found."
    });
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {
        console.error(
            "[HOSHINO ERROR]",
            err
        );

        if (res.headersSent) {
            return next(err);
        }

        res.status(500).json({
            error:
                "Internal Hoshino server error."
        });
    }
);

/* =========================================================
   START SERVER
========================================================= */

const server = app.listen(
    PORT,
    "0.0.0.0",
    () => {
        console.log("");
        console.log("=================================");
        console.log("        HOSHINO SERVER");
        console.log("=================================");
        console.log("");
        console.log(
            `Local API: http://localhost:${PORT}`
        );
        console.log(
            `Network API: http://0.0.0.0:${PORT}`
        );
        console.log(
            `Environment: ${NODE_ENV}`
        );
        console.log("");
        console.log(
            "Allowed local website origins:"
        );
        console.log(
            " - localhost (any port)"
        );
        console.log(
            " - 127.0.0.1 (any port)"
        );
        console.log(
            " - hoshinorevival.github.io"
        );
        console.log("");
        console.log(
            "Hoshino API is running."
        );
        console.log("=================================");
        console.log("");
    }
);

/* =========================================================
   SHUTDOWN
========================================================= */

function shutdown(signal) {
    console.log("");
    console.log(
        `Received ${signal}. Shutting down...`
    );

    server.close(() => {
        try {
            db.close();

            console.log(
                "Database closed."
            );
        } catch (error) {
            console.error(error);
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

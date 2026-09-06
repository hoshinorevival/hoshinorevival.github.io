const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";


/* =========================================
   DATABASE
========================================= */

const db = new Database("hoshino.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");


/* =========================================
   SECURITY
========================================= */

app.disable("x-powered-by");

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    express.json({
        limit: "1mb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "1mb"
    })
);


/* =========================================
   CORS
========================================= */

const allowedOrigins = [
    "https://hoshinorevival.github.io"
];

app.use(
    cors({
        origin: function (origin, callback) {

            // Allow requests with no Origin
            // such as local tools/server requests.
            if (!origin) {
                return callback(null, true);
            }

            if (
                allowedOrigins.includes(origin) ||
                /^https?:\/\/localhost(?::\d+)?$/.test(origin) ||
                /^https?:\/\/127\.0\.0\.1(?::\d+)?$/.test(origin)
            ) {
                return callback(null, true);
            }

            return callback(
                new Error("Origin not allowed by CORS.")
            );
        },

        credentials: true
    })
);


/* =========================================
   SESSION
========================================= */

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

            // 30 days
            maxAge: 1000 * 60 * 60 * 24 * 30
        }
    })
);


/* =========================================
   REQUEST LOGGER
========================================= */

app.use((req, res, next) => {

    const started = Date.now();

    res.on("finish", () => {

        const duration =
            Date.now() - started;

        console.log(
            `${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`
        );
    });

    next();
});


/* =========================================
   HELPERS
========================================= */

function requireAuth(req, res, next) {

    if (
        !req.session ||
        !req.session.userId
    ) {
        return res.status(401).json({
            success: false,
            message: "You must be signed in."
        });
    }

    next();
}


function requireOwner(req, res, next) {

    if (
        !req.session ||
        !req.session.userId
    ) {
        return res.status(401).json({
            success: false,
            message: "You must be signed in."
        });
    }

    const user =
        db.prepare(
            `
            SELECT id, username, role
            FROM users
            WHERE id = ?
            `
        ).get(req.session.userId);

    if (!user) {

        req.session.destroy(() => {});

        return res.status(401).json({
            success: false,
            message: "Invalid session."
        });
    }

    if (user.role !== "owner") {

        return res.status(403).json({
            success: false,
            message: "Owner access required."
        });
    }

    req.currentUser = user;

    next();
}


/* =========================================
   ROOT
========================================= */

app.get("/", (req, res) => {

    res.json({
        name: "Hoshino",
        status: "online",
        message: "Hoshino API is running."
    });
});


/* =========================================
   HEALTH
========================================= */

app.get("/api/health", (req, res) => {

    res.json({
        name: "Hoshino",
        status: "online",
        message: "Hoshino API is running."
    });
});


/* =========================================
   STATUS
========================================= */

app.get("/api/status", (req, res) => {

    res.json({
        name: "Hoshino",
        status: "online",
        maintenance: true
    });
});


/* =========================================
   REGISTER
========================================= */

app.post("/api/register", async (req, res) => {

    try {

        const {
            username,
            password,
            birthDate
        } = req.body;

        if (
            typeof username !== "string" ||
            typeof password !== "string" ||
            typeof birthDate !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message: "Missing required information."
            });
        }


        const cleanUsername =
            username.trim();


        if (
            !/^[A-Za-z0-9_]{3,20}$/.test(
                cleanUsername
            )
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Username must be 3-20 characters and contain only letters, numbers, and underscores."
            });
        }


        if (password.length < 6) {

            return res.status(400).json({
                success: false,
                message:
                    "Password must contain at least 6 characters."
            });
        }


        const existing =
            db.prepare(
                `
                SELECT id
                FROM users
                WHERE username = ?
                `
            ).get(cleanUsername);


        if (existing) {

            return res.status(409).json({
                success: false,
                message:
                    "That username is already taken."
            });
        }


        const passwordHash =
            await bcrypt.hash(
                password,
                12
            );


        const result =
            db.prepare(
                `
                INSERT INTO users
                (
                    username,
                    password_hash,
                    birth_date,
                    role,
                    created_at
                )
                VALUES
                (
                    ?,
                    ?,
                    ?,
                    'user',
                    datetime('now')
                )
                `
            ).run(
                cleanUsername,
                passwordHash,
                birthDate
            );


        return res.status(201).json({
            success: true,
            message:
                "Account created successfully.",
            userId: result.lastInsertRowid
        });

    }

    catch (error) {

        console.error(
            "Registration error:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Could not create account."
        });
    }
});


/* =========================================
   LOGIN
========================================= */

app.post("/api/login", async (req, res) => {

    try {

        const {
            username,
            password
        } = req.body;


        if (
            typeof username !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Username and password are required."
            });
        }


        const user =
            db.prepare(
                `
                SELECT
                    id,
                    username,
                    password_hash,
                    birth_date,
                    role,
                    created_at
                FROM users
                WHERE username = ?
                `
            ).get(
                username.trim()
            );


        if (!user) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid username or password."
            });
        }


        const passwordMatches =
            await bcrypt.compare(
                password,
                user.password_hash
            );


        if (!passwordMatches) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid username or password."
            });
        }


        /*
            Destroy any old session first.
            This prevents session fixation.
        */

        req.session.regenerate(
            (error) => {

                if (error) {

                    console.error(
                        "Session regeneration error:",
                        error
                    );

                    return res.status(500).json({
                        success: false,
                        message:
                            "Could not create login session."
                    });
                }


                /*
                    Store ONLY the user ID
                    inside the session.
                */

                req.session.userId =
                    user.id;


                req.session.username =
                    user.username;


                /*
                    Explicitly save the session
                    before responding.
                */

                req.session.save(
                    (saveError) => {

                        if (saveError) {

                            console.error(
                                "Session save error:",
                                saveError
                            );

                            return res.status(500).json({
                                success: false,
                                message:
                                    "Could not save login session."
                            });
                        }


                        return res.json({

                            success: true,

                            message:
                                "Logged in successfully.",

                            user: {
                                id: user.id,
                                username: user.username,
                                role: user.role
                            }

                        });

                    }
                );
            }
        );

    }

    catch (error) {

        console.error(
            "Login error:",
            error
        );

        return res.status(500).json({
            success: false,
            message:
                "Login failed."
        });
    }
});


/* =========================================
   CURRENT SESSION
========================================= */

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


    const user =
        db.prepare(
            `
            SELECT
                id,
                username,
                role,
                birth_date,
                created_at
            FROM users
            WHERE id = ?
            `
        ).get(
            req.session.userId
        );


    if (!user) {

        req.session.destroy(() => {});

        return res.json({
            loggedIn: false,
            user: null
        });
    }


    /*
        Refresh the session lifetime
        because rolling=true is enabled.
    */

    req.session.touch();


    res.json({
        loggedIn: true,

        user: {
            id: user.id,
            username: user.username,
            role: user.role,
            birthDate: user.birth_date,
            createdAt: user.created_at
        }
    });
});


/* =========================================
   LOGOUT
========================================= */

app.post("/api/logout", (req, res) => {

    if (!req.session) {

        return res.json({
            success: true,
            message: "Already logged out."
        });
    }


    req.session.destroy(
        (error) => {

            if (error) {

                console.error(
                    "Logout error:",
                    error
                );

                return res.status(500).json({
                    success: false,
                    message:
                        "Could not log out."
                });
            }


            res.clearCookie(
                "hoshino.sid",
                {
                    httpOnly: true,
                    secure: IS_PRODUCTION,
                    sameSite: IS_PRODUCTION
                        ? "none"
                        : "lax"
                }
            );


            res.json({
                success: true,
                message:
                    "Logged out successfully."
            });
        }
    );
});


/* =========================================
   PROFILE
========================================= */

app.get(
    "/api/profile",
    requireAuth,
    (req, res) => {

        const user =
            db.prepare(
                `
                SELECT
                    id,
                    username,
                    birth_date,
                    role,
                    created_at
                FROM users
                WHERE id = ?
                `
            ).get(
                req.session.userId
            );


        if (!user) {

            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }


        res.json({
            success: true,
            user
        });
    }
);


/* =========================================
   MY STATS
========================================= */

app.get(
    "/api/my-stats",
    requireAuth,
    (req, res) => {

        const badges =
            db.prepare(
                `
                SELECT COUNT(*) AS count
                FROM user_badges
                WHERE user_id = ?
                `
            ).get(
                req.session.userId
            );


        res.json({
            success: true,

            stats: {
                badges: badges.count
            }
        });
    }
);


/* =========================================
   BADGES
========================================= */

app.get(
    "/api/badges",
    (req, res) => {

        const badges =
            db.prepare(
                `
                SELECT
                    id,
                    name,
                    description,
                    icon,
                    created_at
                FROM badges
                ORDER BY id ASC
                `
            ).all();


        res.json({
            success: true,
            badges
        });
    }
);


/* =========================================
   MY BADGES
========================================= */

app.get(
    "/api/my-badges",
    requireAuth,
    (req, res) => {

        const badges =
            db.prepare(
                `
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
                `
            ).all(
                req.session.userId
            );


        res.json({
            success: true,
            badges
        });
    }
);


/* =========================================
   USER BADGES
========================================= */

app.get(
    "/api/users/:id/badges",
    (req, res) => {

        const userId =
            Number(req.params.id);


        if (!Number.isInteger(userId)) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid user ID."
            });
        }


        const badges =
            db.prepare(
                `
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
                `
            ).all(userId);


        res.json({
            success: true,
            badges
        });
    }
);


/* =========================================
   CHANGE PASSWORD
========================================= */

app.post(
    "/api/change-password",
    requireAuth,
    async (req, res) => {

        try {

            const {
                currentPassword,
                newPassword
            } = req.body;


            if (
                typeof currentPassword !== "string" ||
                typeof newPassword !== "string"
            ) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Both passwords are required."
                });
            }


            if (newPassword.length < 6) {

                return res.status(400).json({
                    success: false,
                    message:
                        "New password must contain at least 6 characters."
                });
            }


            const user =
                db.prepare(
                    `
                    SELECT
                        id,
                        password_hash
                    FROM users
                    WHERE id = ?
                    `
                ).get(
                    req.session.userId
                );


            if (!user) {

                return res.status(404).json({
                    success: false,
                    message:
                        "User not found."
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
                    message:
                        "Current password is incorrect."
                });
            }


            const newHash =
                await bcrypt.hash(
                    newPassword,
                    12
                );


            db.prepare(
                `
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
                `
            ).run(
                newHash,
                user.id
            );


            res.json({
                success: true,
                message:
                    "Password changed successfully."
            });

        }

        catch (error) {

            console.error(
                "Password change error:",
                error
            );

            res.status(500).json({
                success: false,
                message:
                    "Could not change password."
            });
        }
    }
);


/* =========================================
   OWNER - FIND USER
========================================= */

app.get(
    "/api/owner/users/:id",
    requireOwner,
    (req, res) => {

        const id =
            Number(req.params.id);


        if (!Number.isInteger(id)) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid user ID."
            });
        }


        const user =
            db.prepare(
                `
                SELECT
                    id,
                    username,
                    birth_date,
                    role,
                    created_at
                FROM users
                WHERE id = ?
                `
            ).get(id);


        if (!user) {

            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });
        }


        res.json({
            success: true,
            user
        });
    }
);


/* =========================================
   OWNER - AWARD BADGE
========================================= */

app.post(
    "/api/owner/users/:userId/badges/:badgeId",
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
                message:
                    "Invalid ID."
            });
        }


        const user =
            db.prepare(
                "SELECT id FROM users WHERE id = ?"
            ).get(userId);


        const badge =
            db.prepare(
                "SELECT id FROM badges WHERE id = ?"
            ).get(badgeId);


        if (!user || !badge) {

            return res.status(404).json({
                success: false,
                message:
                    "User or badge not found."
            });
        }


        db.prepare(
            `
            INSERT OR IGNORE INTO user_badges
            (
                user_id,
                badge_id,
                awarded_at
            )
            VALUES
            (
                ?,
                ?,
                datetime('now')
            )
            `
        ).run(
            userId,
            badgeId
        );


        res.json({
            success: true,
            message:
                "Badge awarded."
        });
    }
);


/* =========================================
   OWNER - REMOVE BADGE
========================================= */

app.delete(
    "/api/owner/users/:userId/badges/:badgeId",
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
                message:
                    "Invalid ID."
            });
        }


        db.prepare(
            `
            DELETE FROM user_badges
            WHERE user_id = ?
            AND badge_id = ?
            `
        ).run(
            userId,
            badgeId
        );


        res.json({
            success: true,
            message:
                "Badge removed."
        });
    }
);


/* =========================================
   404
========================================= */

app.use(
    (req, res) => {

        res.status(404).json({
            success: false,
            message:
                "Hoshino API endpoint not found."
        });
    }
);


/* =========================================
   ERROR HANDLER
========================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "Server error:",
            error
        );


        if (res.headersSent) {
            return next(error);
        }


        res.status(500).json({
            success: false,
            message:
                "Internal Hoshino server error."
        });
    }
);


/* =========================================
   START SERVER
========================================= */

const server =
    app.listen(
        PORT,
        "0.0.0.0",
        () => {

            console.log(
                "================================"
            );

            console.log(
                "       HOSHINO API SERVER"
            );

            console.log(
                "================================"
            );

            console.log(
                `API: http://localhost:${PORT}`
            );

            console.log(
                `Environment: ${
                    IS_PRODUCTION
                        ? "production"
                        : "development"
                }`
            );

            console.log(
                "Session persistence: 30 days"
            );

            console.log(
                "================================"
            );
        }
    );


/* =========================================
   GRACEFUL SHUTDOWN
========================================= */

function shutdown(signal) {

    console.log(
        `${signal} received. Shutting down...`
    );


    server.close(() => {

        db.close();

        console.log(
            "Hoshino server stopped."
        );

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

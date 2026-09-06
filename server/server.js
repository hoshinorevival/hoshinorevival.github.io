const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = 3000;

// =========================
// Middleware
// =========================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret:
      process.env.HOSHINO_SESSION_SECRET ||
      "CHANGE_THIS_SECRET_BEFORE_PRODUCTION",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true
    }
  })
);

// =========================
// Database
// =========================

const db = new Database("hoshino.db");

db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    birth_date TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS badges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL,
    icon TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS user_badges (
    user_id INTEGER NOT NULL,
    badge_id INTEGER NOT NULL,
    awarded_at DATETIME DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id, badge_id),

    FOREIGN KEY (user_id)
      REFERENCES users(id)
      ON DELETE CASCADE,

    FOREIGN KEY (badge_id)
      REFERENCES badges(id)
      ON DELETE CASCADE
  );
`);

// =========================
// Default badges
// =========================

const badges = [
  ["Owner", "Hoshino owner.", "👑"],
  ["Developer", "Hoshino developer.", "🛠️"],
  ["Administrator", "Hoshino administrator.", "🛡️"],
  ["Moderator", "Hoshino moderator.", "🔨"],
  ["Early Supporter", "Supported Hoshino early on.", "⭐"],
  ["Beta Tester", "Participated in Hoshino testing.", "🎮"]
];

const insertBadge = db.prepare(`
  INSERT OR IGNORE INTO badges
  (name, description, icon)
  VALUES (?, ?, ?)
`);

for (const badge of badges) {
  insertBadge.run(...badge);
}

// =========================
// Helpers
// =========================

function is13OrOlder(birthDate) {
  const birthday = new Date(birthDate);

  if (Number.isNaN(birthday.getTime())) {
    return false;
  }

  const today = new Date();

  let age = today.getFullYear() - birthday.getFullYear();

  const monthDifference =
    today.getMonth() - birthday.getMonth();

  if (
    monthDifference < 0 ||
    (
      monthDifference === 0 &&
      today.getDate() < birthday.getDate()
    )
  ) {
    age--;
  }

  return age >= 13;
}

function requireLogin(req, res, next) {
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
    .prepare("SELECT role FROM users WHERE id = ?")
    .get(req.session.userId);

  if (!user || user.role !== "owner") {
    return res.status(403).json({
      error: "Owner access required."
    });
  }

  next();
}

// =========================
// API status
// =========================

app.get("/", (req, res) => {
  res.json({
    name: "Hoshino",
    status: "online",
    message: "Hoshino API is running."
  });
});

// =========================
// Register
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

    if (!is13OrOlder(birth_date)) {
      return res.status(400).json({
        error: "You must be at least 13 years old."
      });
    }

    const existingUser = db
      .prepare(
        "SELECT id FROM users WHERE username = ?"
      )
      .get(username);

    if (existingUser) {
      return res.status(409).json({
        error: "Username is already taken."
      });
    }

    const passwordHash = await bcrypt.hash(
      password,
      12
    );

    const result = db
      .prepare(`
        INSERT INTO users
        (username, password_hash, birth_date, role)
        VALUES (?, ?, ?, 'user')
      `)
      .run(
        username,
        passwordHash,
        birth_date
      );

    res.json({
      success: true,
      userId: result.lastInsertRowid
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

// =========================
// Login
// =========================

app.post("/api/login", async (req, res) => {
  try {
    const {
      username,
      password
    } = req.body;

    const user = db
      .prepare(`
        SELECT
          id,
          username,
          password_hash,
          role
        FROM users
        WHERE username = ?
      `)
      .get(username);

    if (!user) {
      return res.status(401).json({
        error: "Invalid username or password."
      });
    }

    const validPassword =
      await bcrypt.compare(
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
// Current user
// =========================

app.get("/api/me", requireLogin, (req, res) => {
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
    .get(req.session.userId);

  res.json(user);
});

// =========================
// Logout
// =========================

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

// =========================
// Change password
// =========================

app.post(
  "/api/change-password",
  requireLogin,
  async (req, res) => {
    try {
      const {
        currentPassword,
        newPassword
      } = req.body;

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          error:
            "Current and new passwords are required."
        });
      }

      const user = db
        .prepare(`
          SELECT password_hash
          FROM users
          WHERE id = ?
        `)
        .get(req.session.userId);

      const validPassword =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );

      if (!validPassword) {
        return res.status(401).json({
          error:
            "Current password is incorrect."
        });
      }

      const newHash =
        await bcrypt.hash(newPassword, 12);

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
  }
);

// =========================
// Get user's badges
// =========================

app.get(
  "/api/users/:id/badges",
  (req, res) => {
    const userBadges = db
      .prepare(`
        SELECT
          badges.id,
          badges.name,
          badges.description,
          badges.icon,
          user_badges.awarded_at
        FROM user_badges
        JOIN badges
          ON badges.id = user_badges.badge_id
        WHERE user_badges.user_id = ?
        ORDER BY user_badges.awarded_at ASC
      `)
      .all(req.params.id);

    res.json(userBadges);
  }
);

// =========================
// Owner awards badge
// =========================

app.post(
  "/api/admin/users/:userId/badges",
  requireOwner,
  (req, res) => {
    const {
      badgeId
    } = req.body;

    const userId = req.params.userId;

    const user = db
      .prepare(
        "SELECT id FROM users WHERE id = ?"
      )
      .get(userId);

    if (!user) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    const badge = db
      .prepare(
        "SELECT id FROM badges WHERE id = ?"
      )
      .get(badgeId);

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
      userId,
      badgeId
    );

    res.json({
      success: true
    });
  }
);

// =========================
// Start Hoshino server
// =========================

app.listen(PORT, () => {
  console.log(
    `Hoshino server running at http://localhost:${PORT}`
  );
});
/** User class for message.ly */
const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    let hashedPassword = await bcrypt.hash(password, 12);

    let result = db.query(
      `insert into users (username, password, first_name, last_name, phone, join_at) values ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) returning username, password, first_name, last_name, phone`,
      [username, password, first_name, last_name, phone]
    );
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    let result = await db.query(
      `select password from users where username = $1`,
      [username]
    );

    let user = result.rows[0];

    if (user) {
      let match = await bcrypt.compare(password, user.password);
      return match;
    } else {
      throw new ExpressError("Invalid Username or Password", 401);
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `update users set last_login_at = CURRENT_TIMESTAMP where username = $1 returning username`,
      [username]
    );

    if (result.rows.length === 0) {
      throw new ExpressError("User Not Found", 404);
    }
    return result.rows[0];
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(`select * from users`);
    return result.rows[0];
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(`select * from users where username = $1`, [
      username,
    ]);

    if (result.rows.length === 0) {
      throw new ExpressError("User not Found", 404);
    }
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id,
              m.to_username,
              u.first_name,
              u.last_name,
              u.phone,
              m.body,
              m.sent_at,
              m.read_at
      FROM messages as m
      JOIN users as u ON m.to_username = u.username
      WHERE from_username = $1`,
      [username]
    );

    return result.rows.map((msg) => ({
      id: msg.id,
      to_user: {
        username: msg.to_username,
        first_name: msg.first_name,
        last_name: msg.last_name,
        phone: msg.phone,
      },
      body: msg.body,
      sent_at: msg.sent_at,
      read_at: msg.read_at,
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `SELECT m.id,
              m.from_username,
              u.first_name,
              u.last_name,
              u.phone,
              m.body,
              m.sent_at,
              m.read_at
      FROM messages as m
      JOIN users as u ON m.from_username = u.username
      WHERE to_username = $1`,
      [username]
    );

    return result.rows.map((msg) => ({
      id: msg.id,
      from_user: {
        username: msg.from_username,
        first_name: msg.first_name,
        last_name: msg.last_name,
        phone: msg.phone,
      },
      body: msg.body,
      sent_at: msg.sent_at,
      read_at: msg.read_at,
    }));
  }
}

module.exports = User;

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const ExpressError = require("../expressError");
const db = require("../db");
const { SECRET_KEY } = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async function (req, res, next) {
  try {
    const username = req.body.username;
    const password = req.body.password;

    let result = await db.query(
      `
        SELECT username, password FROM users 
        WHERE username = $1`,
      [username]
    );

    let user = result.rows[0];

    if (user) {
      if ((await bcrypt.compare(password, user.password)) === true) {
        let token = jwt.sign({ username }, SECRET_KEY);
        return res.json({ token });
      }
    } else {
      throw new ExpressError("Invalid user or password.", 400);
    }
  } catch (err) {
    return next(err);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async function (req, res, next) {
  try {
    const username = req.body.username;
    const password = req.body.password;

    const existingUser = await db.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );
    if (existingUser.rows.length !== 0) {
      throw new ExpressError("Username already taken", 400);
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const result = await db.query(
      `
        INSERT INTO users (username, password) 
        VALUES ($1, $2)
        RETURNING username`,
      [username, hashedPassword]
    );

    return res.json(result.rows[0]);
  } catch (err) {
    return next(err);
  }
});

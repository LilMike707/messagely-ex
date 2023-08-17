const express = require("express");

const Router = require("express").Router;
const Message = require("../models/message");
const { ensureLoggedIn } = require("../middleware/auth");

const ExpressError = require("../expressError");
const db = require("../db");
const { SECRET_KEY } = require("../config");

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/

router.get("/", ensureLoggedIn, async function (req, res, next) {
  try {
    // check for login credentials
    let id = req.params.id;
    let message = await Message.get(id);

    return res.json({ message });
  } catch (err) {
    return next(err);
  }
});

/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/

router.get("/:username", ensureLoggedIn, async function (req, res, next) {
  try {
    // check for login credentials
    let username = req.params.username;
    let user = await User.get(username);

    return res.json({ user });
  } catch (err) {
    return next(err);
  }
});

/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/to", ensureLoggedIn, async function (req, res, next) {
  try {
    // check for login credentials
    let username = req.params.username;
    let user = await User.get(username);

    return res.json({ user });
  } catch (err) {
    return next(err);
  }
});

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

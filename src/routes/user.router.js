const { router } = require('../app');
const { getAll, create, getOne, remove, update, verifyUser, login, logged, resetPassword, updatePassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT');

const routerUser = express.Router();

routerUser.route('/')
  .get(verifyJWT, getAll)
  .post(create);

routerUser.route('/login')
  .post(login)

routerUser.route('/me')
  .get(verifyJWT, logged)

routerUser.route('/reset_password')
  .post(resetPassword)



routerUser.route("/verify/:code")
  .get(verifyUser)

routerUser.route("/reset_password/:code")
  .post(updatePassword)

routerUser.route('/:id')
  .get(verifyJWT, getOne)
  .delete(verifyJWT, remove)
  .put(verifyJWT, update);

module.exports = routerUser;
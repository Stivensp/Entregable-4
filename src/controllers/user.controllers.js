const catchError = require('../utils/catchError');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const { sendEmail } = require('../utils/sendEmail');
const EmailCode = require('../models/EmailCode');
const jwt = require('jsonwebtoken')


const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  User.prototype.toJSON = function () {
    const values = Object.assign({}, this.get());
    delete values.password;
    return values;
  }
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { password, email, firstName, frontBaseUrl } = req.body

  const hashedPassword = await bcrypt.hash(password, 10)


  const newBody = { ...req.body, password: hashedPassword }
  const result = await User.create(newBody);
  User.prototype.toJSON = function () {
    const values = Object.assign({}, this.get());
    delete values.password;
    return values;
  }
 
  const code = require('crypto').randomBytes(64).toString('hex')

 
  await EmailCode.create(
    {
      code,
      userId: result.id
    }
  )


  sendEmail({
    to: email,
    subject: 'Verify email ',
    html: `
      <div>
          <a href="${frontBaseUrl}/verify_email/${code}">Verificar email</a>
      </div>
   
`
  })


  return res.status(201).json(result);
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  User.prototype.toJSON = function () {
    const values = Object.assign({}, this.get());
    delete values.password;
    return values;
  }
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;

  const fieldsToDelete = ['email', 'password', 'isVerifed']

  fieldsToDelete.forEach(field => {
    delete req.body[field]
  })



  const result = await User.update(
    req.body,
    { where: { id }, returning: true }
  );
  if (result[0] === 0) return res.sendStatus(404);
  return res.json(result[1][0]);
});


const verifyUser = catchError(async (req, res) => {
  const { code } = req.params

  const userCode = await EmailCode.findOne({ where: { code } })

  if (!userCode) return res.status(401).json({ error: 'User not found' })

  const user = await User.findByPk(userCode.userId)

  await user.update(
    { isVerifed: true }
  )

  await userCode.destroy()


  return res.json(user)
})

const login = catchError(async (req, res) => {
  const { email, password } = req.body

  const user = await User.findOne({ where: { email } })
  if (!user) res.sendStatus(401)

  const isValid = await bcrypt.compare(password, user.password)
  if (!isValid) res.sendStatus(401)

  const token = jwt.sign(
    { user },
    process.env.TOKEN_SECRET,
    { expiresIn: "1d" }
  )

  return res.json({ user, token })
})

const logged = catchError(async (req, res) => {
  const user = req.userz
  return res.json(user)
})
const resetPassword = catchError(async (req, res) => {
  const { email, frontBaseUrl } = req.body

  const user = await User.findOne({ where: { email } })
  if (!user) return res.status(401).json({ error: "User not found" })

  const code = require('crypto').randomBytes(64).toString('hex')

  await EmailCode.create({ code, userId: user.id })

  const firstName = user.firstName
  sendEmail({
    to: email,
    subject: 'Reset password',
    html: `

      <div >
          <a href="${frontBaseUrl}/reset_password/${code}" >Reset password</a>
      </div>
`
  })


  return res.json(user)

})


const updatePassword = catchError(async (req, res) => {
  const { code } = req.params
  const { password } = req.body

  const codeUser = await EmailCode.findOne({ where: { code } })
  if (!codeUser) return res.status(401).json({ error: "User not found" })

  const user = await User.findByPk(codeUser.userId)

  const newPassword = await bcrypt.hash(password, 10)

  const userUpdate = await user.update({
    password: newPassword
  })

  await codeUser.destroy()


  return res.json(userUpdate)

})


module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyUser,
  login,
  logged,
  resetPassword,
  updatePassword
}

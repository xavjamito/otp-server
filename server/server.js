require('dotenv').config()

const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')

const accountSID = process.env.ACCOUNT_SID
const authToken = process.env.AUTH_TOKEN
const twilioClient = require('twilio')(accountSID, authToken)

const crypto = require('crypto')
const smsKey = process.env.SMS_SECRET_KEY
const twilioNum = process.env.TWILIO_PHONE_NUMBER

const jwt = require('jsonwebtoken')
const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN
const JWT_REFRESH_TOKEN = process.env.JWT_REFRESH_TOKEN
let refreshTokens = []

const app = express()
app.use(express.json())

app.use(cors({ origin: 'http://localhost:3000', credentials: true }))
app.use(cookieParser())

app.post('/sendOTP', (req, res) => {
  const phone = req.body.phone
  const otp = Math.floor(10000 + Math.random() * 900000)
  const ttl = 1 * 30 * 1000
  const expires = Date.now() + ttl
  const data = `${phone}.${otp}.${expires}`
  const hash = crypto.createHmac('sha256', smsKey).update(data).digest('hex')
  const fullHash = `${hash}.${expires}`
  const expiresString = new Date(expires).toString()

  twilioClient.messages.create({
    body: `Your One-Time-Password is ${otp}. It will expire in 30 seconds on ${expiresString}`,
    from: twilioNum,
    to: phone
  })
  .then((messages) => console.log(messages))
  .catch((err) => console.error(err))

  res.status(200).send({ phone, hash: fullHash, otp, expiresString })
})

app.post('/verifyOTP', (req, res) => {
  const phone = req.body.phone
  const hash = req.body.hash
  const otp = req.body.otp
  let [ hashValue, expires ] = hash.split('.')

  let now = Date.now()
  if (now > parseInt(expires)) {
    return res.status(504).send({ msg: 'OTP has expired. Please make another request.' })
  }

  let data = `${phone}.${otp}.${expires}`
  let newCalculatedHash = crypto.createHmac('sha256', smsKey).update(data).digest('hex')
  if (newCalculatedHash === hashValue) {
    console.log('user verified')
    const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, { expiresIn: '30s' })
    const refreshToken = jwt.sign({ data: phone }, JWT_REFRESH_TOKEN, { expiresIn: '1y' })
    refreshTokens.push(refreshToken)

    res
    .status(202)
    .cookie('accessToken', accessToken, {
      expires: new Date(new Date().getTime() + 30 * 1000),
      sameSite: 'strict',
      httpOnly: true
    })
    .cookie('refreshToken', refreshToken, {
      expires: new Date(new Date().getTime() + 31557600000),
      sameSite: 'strict',
      httpOnly: true
    })
    .cookie('authSession', true, { expires: new Date(new Date().getTime() + 30 * 1000), sameSite: 'strict' })
    .cookie('refreshTokenID', true, { expires: new Date(new Date().getTime() + 31557600000), sameSite: 'strict' })
    .send({ msg: 'Device Verified' })
  }
})

const authenticateUser = async (req, res, next) => {
  const accessToken = req.cookies.accessToken
  jwt.verify(accessToken, JWT_AUTH_TOKEN, async (err, phone) => {
    if (phone) {
      req.phone = phone
      next()
    } else if (err.message === "TokenExpiredError") {
      return res.status(403).send({
        success: false,
        msg: 'Access Token has expired.'
      })
    } else {
      console.error(err)
      return res.status(403).send({ err, msg: "User is not authenticated." })
    }
  })
}

app.post('/home', authenticateUser, (req, res) => {
  console.log('HOME: Private Route')
  res.status(202).send('HOME: Private Route')
})

// app.get('/log')

app.listen(process.env.PORT || 4000)

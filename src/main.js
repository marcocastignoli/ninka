const express = require('express')
const bodyParser = require('body-parser');
const mongodb = require('mongodb');
const cors = require('cors')
const jwt = require('jsonwebtoken')
const jwtCheck = require('express-jwt')
const bcrypt = require( 'bcrypt' )
const randomize = require('randomatic')

const MongoClient = mongodb.MongoClient

const _PRIVATE_KEY = 'hello'

const app = express()
app.use(bodyParser.json());
app.use(cors())
app.use(jwtCheck({ secret: _PRIVATE_KEY, algorithms: ['HS256'] }).unless({ path: [/^\/auth\/.*/] }))
app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
      res.status(401).send('invalid_token');
    }
  });

(async ()=>{

    const client = await MongoClient.connect('mongodb://localhost:27017', { useNewUrlParser: true, useUnifiedTopology: true })
    
    const db = client.db('ninka')
    
    app.post('/auth/register/:app', async (req, res) => {
        if (req.body.username && req.params.app) {
            const app =  await db.collection('apps').findOne({ name: req.params.app })
            if (!app) {
                return res.send('wrong_app')
            }
            if (app.auth === 'sms' && !req.body.phone) {
                return res.send('miss_number')
            } else if ((!app.auth || app.auth === 'password') && !req.body.password ) {
                return res.send('miss_password')
            }
            const user =  await db.collection('users').findOne({ name: req.body.username, app: new mongodb.ObjectID(app._id) })
            if (user) {
                return res.send('username_taken')
            }
            try {
                let newUser = {
                    name: req.body.username,
                    app: new mongodb.ObjectID(app._id),
                    active: false
                }
                if (app.auth === 'sms') {
                    newUser['phone'] = req.body.phone
                    const verificationCode = randomize('000000')
                    console.log(verificationCode)
                    const hash = await bcrypt.hash( verificationCode, 10)
                    newUser['verification_code'] = hash
                    const {sendToken} = require('./auth/sms')
                    const sendSms = await sendToken(newUser['phone'], verificationCode, app.sms_content ? app.sms_content : '')
                    if (sendSms.status !== 200) {
                        return res.send('sms_failed')
                    }
                    newUser['active'] = true
                } else {
                    const hash = await bcrypt.hash( req.body.password, 10)
                    newUser['pwd'] = hash
                    newUser['active'] = true
                }
                db.collection('users').insert(newUser)
                return res.send('success')
            } catch (e) {
                console.log(e)
                return res.send('error')
            }
        } else {
            return res.send('miss_arguments')
        }
    })
    
    app.post('/auth/login/:app', async (req, res) => {
        if (req.body.username && req.params.app) {
            const app =  await db.collection('apps').findOne({ name: req.params.app })
            if (!app) {
                return res.send('wrong_app')
            }
            if (app.auth === 'sms' && !req.body.verification_code) {
                return res.send('miss_number')
            } else if ((!app.auth || app.auth === 'password') && !req.body.password ) {
                return res.send('miss_password')
            }
            const user = await db.collection('users').findOne({
                name: req.body.username,
                app: new mongodb.ObjectID(app._id)
            })
            if (!user) {
                return res.send('wrong_username')
            }
            if (!user.active) {
                return res.send('user_inactive')
            }
            if (app.auth === 'sms') {
                if( bcrypt.compareSync( req.body.verification_code, user.verification_code ) ) {
                    const token = jwt.sign({ username: user.username, id: user._id }, _PRIVATE_KEY);
                    return res.send(token)       
                } else {
                    return res.send('wrong_verification_code')
                }
            } else if (!req.body.password ) {
                if( bcrypt.compareSync( req.body.password, user.pwd ) ) {
                    const token = jwt.sign({ username: user.username, id: user._id }, _PRIVATE_KEY);
                    return res.send(token)       
                } else {
                    return res.send('wrong_password')
                }
            }
        } else {
            return res.send('err: inviami username e password')
        }
    })
    
    app.get('/users/my', async function (req, res) {
        try {
            const result = await db.collection('users').findOne({
                _id: new mongodb.ObjectID(req.user.id)
            })
            res.send(result)
        } catch(e) {
            res.send({})
        }
    })

    app.get('/on/:app/can/:user/:permission', async function (req, res) {
        const app =  await db.collection('apps').findOne({ name: req.params.app })
        if (!app) {
            return res.send('wrong_app')
        }
        
        const user = await db.collection('users').findOne({
            name: req.params.user,
            app: new mongodb.ObjectID(app._id)
        })
        if (!user) {
            return res.send('wrong_username')
        }

        const permission = await db.collection('permissions').findOne({
            app: new mongodb.ObjectID(app._id),
            name: req.params.permission
        })
        if (!permission) {
            return res.send('wrong_permission')
        }
        
        return res.send(permission.role.includes(user.role))
    })
    
    app.listen(8888)
})()
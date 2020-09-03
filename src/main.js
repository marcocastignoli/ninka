const express = require('express')
const bodyParser = require('body-parser');
const mongodb = require('mongodb');
const cors = require('cors')
const jwt = require('jsonwebtoken')
const jwtCheck = require('express-jwt')
const bcrypt = require( 'bcrypt' )
const randomize = require('randomatic')
const https = require('https');
const http = require('http');
const fs = require('fs');
const config = require('./config');

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
                return res.status(404).send('wrong_app')
            }
            if (app.auth === 'sms' && !req.body.phone) {
                return res.status(400).send('miss_number')
            } else if ((!app.auth || app.auth === 'password') && !req.body.password ) {
                return res.status(400).send('miss_password')
            }
            const user =  await db.collection('users').findOne({ name: req.body.username, app: new mongodb.ObjectID(app._id) })
            if (user) {
                return res.status(409).send('username_taken')
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
                        return res.status(500).send('sms_failed')
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
                return res.status(500).send('error')
            }
        } else {
            return res.status(400).send('miss_arguments')
        }
    })
    
    app.post('/auth/login/:app', async (req, res) => {
        if (req.body.username && req.params.app) {
            const app =  await db.collection('apps').findOne({ name: req.params.app })
            if (!app) {
                return res.status(404).send('wrong_app')
            }
            if (app.auth === 'sms' && !req.body.verification_code) {
                return res.status(400).send('miss_number')
            } else if ((!app.auth || app.auth === 'password') && !req.body.password ) {
                return res.status(400).send('miss_password')
            }
            const user = await db.collection('users').findOne({
                name: req.body.username,
                app: new mongodb.ObjectID(app._id)
            })
            if (!user) {
                return res.status(404).send('wrong_username')
            }
            if (!user.active) {
                return res.status(401).send('user_inactive')
            }
            if (app.auth === 'sms') {
                if( bcrypt.compareSync( req.body.verification_code, user.verification_code ) ) {
                    const token = jwt.sign({ username: user.username, id: user._id }, _PRIVATE_KEY);
                    return res.send(token)       
                } else {
                    return res.status(401).send('wrong_verification_code')
                }
            } else if (!req.body.password ) {
                if( bcrypt.compareSync( req.body.password, user.pwd ) ) {
                    const token = jwt.sign({ username: user.username, id: user._id }, _PRIVATE_KEY);
                    return res.send(token)       
                } else {
                    return res.status(401).send('wrong_password')
                }
            }
        } else {
            return res.status(400).send('err: inviami username e password')
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
            return res.status(404).send('wrong_app')
        }
        
        const user = await db.collection('users').findOne({
            name: req.params.user,
            app: new mongodb.ObjectID(app._id)
        })
        if (!user) {
            return res.status(404).send('wrong_username')
        }

        const permission = await db.collection('permissions').findOne({
            app: new mongodb.ObjectID(app._id),
            name: req.params.permission
        })
        if (!permission) {
            return res.status(400).send('wrong_permission')
        }
        
        return res.send(permission.role.includes(user.role))
    })
    
    const httpServer = http.createServer(app);

    httpServer.listen(80, () => {
        console.log('HTTP Server running on port 80');
    });

    if (config.https) {
        const httpsServer = https.createServer({
            key: fs.readFileSync(config.https.key),
            cert: fs.readFileSync(config.https.cert),
        }, app);
        httpsServer.listen(443, () => {
            console.log('HTTPS Server running on port 443');
        });
    }

})()
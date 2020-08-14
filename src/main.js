const express = require('express')
const bodyParser = require('body-parser');
const mongodb = require('mongodb');
const cors = require('cors')
const jwt = require('jsonwebtoken')
const jwtCheck = require('express-jwt')
const bcrypt = require( 'bcrypt' )

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
        if (req.body.username && req.body.password && req.params.app) {
            const app =  await db.collection('apps').findOne({ name: req.params.app })
            if (!app) {
                return res.send('wrong_app')
            }
            const user =  await db.collection('users').findOne({ name: req.body.username, app: new mongodb.ObjectID(app._id) })
            if (user) {
                return res.send('username_taken')
            }
            try {
                const hash = await bcrypt.hash( req.body.password, 10)
                db.collection('users').insert({
                    name: req.body.username,
                    pwd: hash,
                    app: new mongodb.ObjectID(app._id)
                })
                return res.send('success')
            } catch (e) {
                return res.send('error')
            }
        } else {
            return res.send('miss_arguments')
        }
    })
    
    app.post('/auth/login/:app', async (req, res) => {
        if (req.body.username && req.body.password && req.params.app) {
            const app =  await db.collection('apps').findOne({ name: req.params.app })
            if (!app) {
                return res.send('wrong_app')
            }
            const user = await db.collection('users').findOne({
                name: req.body.username,
                app: new mongodb.ObjectID(app._id)
            })
            if (!user) {
                return res.send('wrong_username')
            }
            if( bcrypt.compareSync( req.body.password, user.pwd ) ) {
                const token = jwt.sign({ username: user.username, id: user._id }, _PRIVATE_KEY);
                return res.send(token)       
            } else {
                return res.send('wrong_password')
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
    
    app.listen(8888)
})()
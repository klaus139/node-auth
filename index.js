import express from "express"
import Datastore from "nedb-promises"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import appTokens from "./config.js"


const app = express();
app.use(express.json());        // For parsing application/json
app.use(express.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded


const users = Datastore.create("Users.db")
const userRefreshToken = Datastore.create('UserRefreshToken.db')

app.post("/api/auth/register", async(req, res) => {
    try{

        const {name, email, password, role} = req.body
        if(!name || !email || !password){
            return res.status(422).json({message:"Please fill in all the fields (name | email | password)"})
        }

        if (await users.findOne({email})){
            return res.status(409).json({message:"email already exists"})
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await users.insert({
            name, email, password:hashedPassword, role: role ?? 'member'
        })

        return res.status(201).json({message:"user registered successful", id: newUser._id})

    }catch(error){
        return res.status(500).json({message: error.message})
    }
})

app.post("/api/auth/login", async(req, res) => {
    try{

        const {email, password} = req.body;

        if (!email || !password){
            return res.status(422).json({message:"please fill in all the fields"})

        }

        const user = await users.findOne({email})

        if (!user){
            return res.status(401).json({message:'Email or password is invalid'})
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password)

        if(!isPasswordMatch){
            return res.status(401).json({message:'Email or password is invalid'})
        }

        const accessToken = jwt.sign({userId:user._id}, appTokens.accessTokenSecret, {subject:"accessApi", expiresIn: '1h'} )

        const refreshToken = jwt.sign({userId:user._id}, appTokens.refreshTokenSecret, {subject:'refreshToken', expiresIn: '1w'})

        await userRefreshToken.insert({
            refreshToken,
            userId:user._id
        })

        return res.status(200).json({
            id: user._id,
            name: user.name,
            email:user.email,
            accessToken,
            refreshToken
        })



    }catch(error){
        return res.status(500).json({message: error.message})
    }
})

app.post('/api/auth/refresh-token', async(req, res) => {
    try{
        const {refreshToken} = req.body;
        if(!refreshToken){
            return res.status(401).json({
                message:"refresh token not found"
            })
        }

        const decodedRefreshToken = jwy.verify(refreshToken, appTokens.refreshTokenSecret)

    }catch(error){
        if(error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError){
            return res.status(401).json({
                message:"refresh toekn invalid or expired"
            })
        }
        return res.status(500).json({message: error.message})
    }
})

app.get("/api/user/current", ensureAuthenticated ,async(req, res) => {
    try{
        const user = await users.findOne({_id:req.user.id})
        return res.status(200).json({
            id: user._id,
            name:user.name,
            email:user.email
        })

    }catch(error){
        return res.status(500).json({message: error.message})
    }

})

app.get("/api/admin", ensureAuthenticated, authorize(['admin']), async(req, res) => {
    return res.status(200).json({
        message:"only admins can access this route"
    })
})

app.get("/api/moderator", ensureAuthenticated, authorize(['admin','moderator']), async(req, res) => {
    return res.status(200).json({
        message:"only admins and moderators can access this route"
    })
})

async function ensureAuthenticated(req, res, next){
    const accessToken = req.headers.authorization

    if(!accessToken){
        return res.status(401).json({
            message:"Access token not found"
        })
    }
    
    try{
        const decodedAccessToken = jwt.verify(accessToken, appTokens.accessTokenSecret)
        req.user = {id:decodedAccessToken.userId}

        next()

    }catch(error){
        return res.status(401).json({
            message:"Access token invalid or expired"
        })
    }

}

function authorize(roles = []){
    return async function (req, res, next){
        const user = await users.findOne({
            _id: req.user.id
        })

        if(!user || !roles.includes(user.role)){
            return res.status(403).json({
                message: 'Access denied'
            })
        }
        next()
    }
}

app.get('/', (req, res) => {
    res.send("REST API Authentication and Authorization")
})

app.listen(3000, () => console.log('server is running'))
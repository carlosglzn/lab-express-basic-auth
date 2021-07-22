const router = require("express").Router()
const bcryptjs = require("bcryptjs");
const mongoose = require("mongoose");

const User = require("./../models/User.model")


router.get("/signup", (req, res) => {
    res.render("auth/signup")
})

router.post("/signup", (req, res) => {
    
    const { username, password } = req.body
    
    if (!username || !password) {

        return res.render("auth/sigup", {
            msg: "Error: All fields are mandatory. Please provide your username and password."
        })
    }
    
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;

    if (!regex.test(password)) {
        return res.status(500).render("auth/signup", {
            msg: "Error: Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter."
        })
    }
    

    bcryptjs
        .genSalt(10)
        .then(salt => bcryptjs.hash(password,salt))
        .then(hashedPassword => {
            return User.create({
                username,
                password: hashedPassword
            })
        })
        .then(userCreated => {
            console.log("User created:", userCreated)
            res.redirect('/login')
        })
        .catch(e => {
            if (e instanceof mongoose.Error.ValidationError) {
                res.status(500).render("auth/signup", {
                    msg: "Error: Try a valid username"
                })
            } else if (e.code === 11000) {
                res.status(500).render("auth/signup", {
                    msg: "Error: username already taken. Please try another username."
                })
            }
        })
})

// GET Profile Page for current User

router.get('/userprofile', (req, res) => {
    res.render("users/user-profile", { actualUser: req.session.actualUser })
})

// GET - SHOW LOGIN FORM

router.get("/login", (req, res) => {
    res.render("auth/login")
})

// POST - AUTH

router.post("/login", (req, res) => {

    console.log("SESSION ===>",req.session)

    const { username, password } = req.body

    if (!username || !password) {
        return res.render("auth/login", {
            msg: "Error: Please enter both, username and password to login."
        })
    }

    User.findOne({ username })
        .then((userFound) => {

            if (!userFound) {
                return res.render("auth/login", {
                    msg: "Error: Username is not registered. Try other username."
                })
            }

            const authVerif = bcryptjs.compareSync(password, userFound.password)

            if (!authVerif) {
                return res.render("auth/login", {
                    msg: "Error: Incorrect password."
                })
            }

            req.session.actualUser = userFound

            console.log("Updated Session:", req.session)

            return res.redirect("/userprofile")
        })
        .catch((e) => {
            console.log(e)
        })
})

router.post("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.log(err)
        }
        res.redirect("/")
    })
})



module.exports = router
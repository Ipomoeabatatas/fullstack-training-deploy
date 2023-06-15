// Express boilerplate
const express = require('express');
require('dotenv').config();
const mysql = require('mysql2/promise');
const app = express();
const bcrypt = require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');


// set the view engine to ejs
app.set('view engine', 'ejs');

// use the public folder for static files
app.use(express.static('public'));

// enable urlencoded
app.use(express.urlencoded({ extended: false }));

// setup session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}))

// Initailsing passport
app.use(passport.initialize());
app.use(passport.session());

// JWT Config
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET
};

// middleware to make sure user is authenticated
function ensureAuthenticated(req, res, next) {
    console.log(req);
    if (req.isAuthenticated()) {
        return next();
    }
    // Redirect unauthenticated users to the login page
    res.redirect('/login');
}

function ensureRole(allowedRoles) {
    return function (req, res, next) {
        if (req.user && allowedRoles.includes(req.user.role_name)) {
            next();
        } else {
            res.status(403);
            res.send("Forbidden. You don't have the access rights");
        }
    }
}

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
};

async function main() {
    try {
        const db = await mysql.createConnection(dbConfig);
        console.log('Connected to the MySQL database!');

        // serialize user when they log in
        passport.serializeUser((user, done) => {
            // save the user id into the session
            done(null, user.id);
        });

        // id is whatever we have serialize into the session
        passport.deserializeUser(async (id, done) => {
            // retrieve the user from the database
            const [user] = await db.query('SELECT users.*, roles.role_name FROM users JOIN roles on users.role_id = roles.id WHERE users.id = ?', [id]);
            done(null, user[0]);
        })


        // setup passport
        passport.use(new LocalStrategy(async (username, password, done) => {
            try {
                const [user] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
                if (user.length === 0) {
                    return done(null, false, { message: 'Incorrect username.' });
                }
                const match = await bcrypt.compare(password, user[0].password);
                if (!match) {
                    return done(null, false, { message: 'Incorrect password.' });
                }
                return done(null, user[0]);
            } catch (err) {
                return done(err);
            }
        }));

        // JWT Passport Strategy
        // activated when the user access a route protected by JWT
        passport.use(new JwtStrategy(jwtOptions, async (jwt_payload, done) => {
            try {
                const db = await mysql.createConnection(dbConfig);
                const [user] = await db.query('SELECT * FROM users WHERE id = ?', [jwt_payload.id]);
                if (user[0]) {
                    return done(null, user[0]);
                } else {
                    return done(null, false);
                }
            } catch (err) {
                return done(err, false);
            }
        }));

        app.get('/register', async (req, res) => {
            res.render('register');
        })

        app.post('/register', async (req, res) => {
            try {
                const hashedPassword = await bcrypt.hash(req.body.password, 10);
                await db.query('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [req.body.username, hashedPassword, req.body.email]);
                res.redirect('/login');
            } catch (e) {
                console.log(e);
                res.redirect('/register');
            }
        });

        app.get('/profile', ensureAuthenticated, async (req, res) => {
            res.render('profile', { user: req.user });
        })

        app.get('/login', async (req, res) => {
            res.render('login');
        })

        app.post('/login', async (req, res, next) => {
            // use passport to perform authentication
            passport.authenticate('local', (err, user, info) => {
                if (err) { return next(err); }
                if (!user) { return res.redirect('/login'); }
                req.logIn(user, (err) => {
                    if (err) { return next(err); }
                    return res.redirect('/artworks');
                });
            })(req, res, next);
        })

        app.get('/logout', (req, res) => {
            req.logout(function (e) {
                if (e) {
                    console.error('Error destroying session:', err);
                    return res.status(500).send('Error destroying session');
                } else {
                    res.redirect("/login");
                }
            });

        })

        app.get('/artworks', async (req, res) => {
            try {
                const [artworks] = await db.query(`SELECT * FROM artworks JOIN artists 
                  ON artworks.artist_id = artists.id`);
                res.render('artworks', { artworks: artworks });
            } catch (err) {
                console.error(err);
                res.status(500).send('Internal Server Error');
            }
        });

        // Get all artists
        app.get('/artists', async (req, res) => {
            try {
                const [artists] = await db.query('SELECT * FROM artists');
                res.render('artists', { artists: artists });
            } catch (err) {
                console.error(err);
                res.status(500).send('Internal Server Error');
            }
        });

        app.get('/artists/create', [ensureAuthenticated, ensureRole(["admin", "staff"])], async (req, res) => {
            res.render('create-artist');
        })

        app.get('/artists/:id/update', async (req, res) => {
            try {
                const [artist] = await db.query('SELECT * FROM artists WHERE id = ?', [req.params.id]);
                res.render('update-artist', { artist: artist[0] });
            } catch (err) {
                console.error(err);
                res.status(500).send('Internal Server Error');
            }
        });

        // Add a new artist (assuming you have a form to submit data)
        app.post('/artists/create', [ensureAuthenticated, ensureRole(["admin", "staff"])], async (req, res) => {
            try {
                const { name, birth_year, country } = req.body;
                await db.query('INSERT INTO artists (name, birth_year, country) VALUES (?, ?, ?)', [name, birth_year, country]);
                res.redirect('/artists');
            } catch (err) {
                console.error(err);
                res.status(500).send('Internal Server Error');
            }
        });

        app.post('/artists/:id/update', async (req, res) => {
            try {
                const { name, birth_year, country } = req.body;
                await db.query('UPDATE artists SET name = ?, birth_year = ?, country = ? WHERE id = ?', [name, birth_year, country, req.params.id]);
                res.redirect('/artists');
            } catch (err) {
                console.error(err);
                res.status(500).send('Internal Server Error');
            }
        });

        // Delete an artist
        app.post('/artists/:id/delete', async (req, res) => {
            try {
                await db.query('DELETE FROM artists WHERE id = ?', [req.params.id]);
                res.redirect('/artists');
            } catch (err) {
                console.error(err);
                res.status(500).send('Internal Server Error');
            }
        });

        // API
        // New POST /api/login using JWT Strategy
        app.post('/api/login', [express.json()], async (req, res, next) => {
            passport.authenticate('local', { session: false }, (err, user, info) => {
                if (err) { return next(err); }
                if (!user) { return res.status(401).json({ message: 'Invalid credentials' }); }

                const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
                return res.json({ token });
            })(req, res, next);
        });

        // Protected route using JWT
        app.get('/api/profile', passport.authenticate('jwt', { session: false }), async (req, res) => {
            res.json({ message: "You accessed protected API", user: req.user });
        });

        app.listen(process.env.PORT || 3000, () => {
            console.log('Server started on port 3000');
        });
    } catch (err) {
        console.error('Error connecting to the MySQL database:', err);
    }


}
main();


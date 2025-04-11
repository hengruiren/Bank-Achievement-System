const mysql = require('mysql2/promise');
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const port = process.env.PORT || 8080;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const dayjs = require('dayjs');
const cors = require('cors');

require('dotenv').config();
const database = mysql.createPool({
    host: process.env.DB_DOMAIN,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME, 
    port: process.env.DB_PORT,
});

const authenticateToken = (req, res, next) => {
    console.log('authenticate token');
    const token =req.cookies.authtoken;
    if (!token) {
        console.log('\tno token');
        res.json({"result": "ERROR", "message": "No token"});
        return;
    }
    // verify token
    try {
        decoded = jwt.verify(token, process.env.MY_SECRET);
        req.username = decoded.username;
        req.title = decoded.title;
        req.position = decoded.position;
        console.log('\ttoken verified');
        next();
    } catch (err) {
        console.log('\tinvalid token');
        res.json({"result": "ERROR", "message": err.message});
        return;
    }
};

const authenticateAdmin = (req, res, next) => {
    console.log('authenticate admin');
    const token = req.cookies.authtoken;
    if (!token) {
        console.log('\tERR: no token');
        res.json({"result": "ERROR", "message": "No token"});
        return;
    }
    // verify token
    try {
        decoded = jwt.verify(token, process.env.MY_SECRET);
        console.log('\ttoken verified');
        req.username = decoded.username;
        req.title = decoded.title;
        req.position = decoded.position;
        console.log('\tset username, title, position ', req.username, req.title, req.position);
        next();
    } catch (err) {
        console.log('\tERR: invalid token');
        res.json({"result": "ERROR", "message": err.message});
        return;
    }
}

const corsoptions = {
    origin: 'http://localhost:8080',
    credentials: true,
    optionsSuccessStatus: 200
}
// Create API
app.use(cors(corsoptions));
app.use(bodyParser.json());
app.use(cookieParser());

app.use(express.static(path.join(__dirname, './frontend/dist')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, './frontend/dist/index.html'));
});
app.get('/employee', (req, res) => {
    res.sendFile(path.join(__dirname, './frontend/dist/index.html'));
});
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, './frontend/dist/index.html'));
});

app.post('/login', async (req, res) => {
    console.log('login');
    const { username, password, token } = req.body;
    try {
        if (token) {
            console.log('\tuse token to login')
            jwt.verify(token, process.env.MY_SECRET);
            console.log('\ttoken verified');
            res.json({"result": "OK", "message": "Login Success"});
        } else {
            console.log('\tuse username and password to login');
            if (!username || !password) {
                console.log('\tERR: invalid username or password');
                res.json({"result": "ERROR", "message": "Incomplete information"});
                return;
            }
            // connect to database
            var [result, field] = await database.execute(
                'SELECT name, password, title, position FROM Users WHERE name = ?',
                [username]
            );
            if (result.length == 0) {
                console.log('\tERR: invalid username', username);
                res.json({"result": "ERROR", "message": "Username or password is incorrect"});
                return;
            }
            const user = result[0];
            console.log('\tvalid username', user.name);
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                console.log('\tERR: invalid password');
                res.json({"result": "ERROR", "message": "Username or password is incorrect"});
            }
            console.log('\tvalid password');
            // generate token
            const authtoken = jwt.sign(
                {
                    username: user.name, 
                    title: user.title,
                    position: user.position
                },
                process.env.MY_SECRET,
                { expiresIn: '24h' }
            );
            console.log('\ttoken generated');
            res.cookie('authtoken', authtoken, { httpOnly: true }).json({
                "result": "OK", 
                "message": "Login Success",
                "data": {
                    "username": user.name,
                    "title": user.title,
                    "position": user.position,
                    "authtoken": authtoken
                }
            });
        }
    } catch (err) {
        console.log('\tERR: ', err.message);
        res.json({"result": "ERROR", "message": err.message});
    }
});

app.post('/register', async (req, res) => {
    console.log('register')
    const { username, password, position, title } = req.body;
    console.log(req.body);
    if (!username || !password || !position || !title) {
        console.log('\tERR: invalid general information');
        res.json({"result": "ERROR", "message": "Incomplete information"});
        return;
    }
    try {
        // check if username exists
        var [result, field] = await database.execute(
            'SELECT name FROM Users WHERE name = ?',
            [username]
        );

        if (result.length > 0) {
            console.log('\tERR: username already exists');
            res.json({"result": "ERROR", "message": "Username already exists"});
            return;
        }
        console.log('\tvalid username');
        // hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        console.log('\tpassword hashed');
        // insert user
        var [insertResult, field] = await database.execute(
            'INSERT INTO Users (name, password, title, position) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, title, position]
        );
        console.log('\tuser inserted');
        // generate token
        const authtoken = jwt.sign(
            {
                username: username, 
                title: title,
                position: position
            },
            process.env.MY_SECRET,
            { expiresIn: '24h' }
        );
        console.log('\ttoken generated');
        res.cookie('authtoken', authtoken, { httpOnly: true }).json({
            "result": "OK", 
            "message": "Sign up success", 
            "data": {
                "username": username,
                "title": title,
                "position": position, 
                "authtoken": authtoken
            }
        });
    } catch (err) {
        console.log('\tERR: ', err.message);
        res.json({"result": "ERROR", "message": err.message});
    }
});

app.get('/checkcookie', authenticateToken, (req, res) => {
    res.json({
        "result": "OK", 
        "message": "Cookie is valid", 
        "data": {
            "username": req.username,
            "title": req.title,
            "position": req.position
        }
    });
});

app.get('/data', authenticateAdmin, async (req, res) => {
    const max_date = req.query.max_date;
    const min_date = req.query.min_date;
    console.log('get data');
    try {
        // const query = `SELECT  FROM Achievements WHERE date BETWEEN '${min_date}' AND '${max_date}' ORDER BY date DESC, score DESC, position, title, name`;
        const query = `SELECT name, title, position, SUM(score) AS score FROM Achievements WHERE date BETWEEN '${min_date}' AND '${max_date}' GROUP BY name, title, position ORDER BY score DESC, position, title, name`;
        var [data, field] = await database.execute(query);
        console.log('\tdata retrieved');
        // calculate each person's total score in the range

        res.json({"result": "OK", "message": "Data retrieved", "data": data});
    } catch (err) {
        console.log('\tERR: ', err.message);
        res.json({"result": "ERROR", "message": err.message});
    }
});

app.get('/branch_compare', authenticateAdmin, async (req, res) => {
    const max_date = req.query.max_date;
    const min_date = req.query.min_date;
    console.log('get branch compare data');
    try {
        // const query = `SELECT position, title, SUM(score) AS score FROM Achievements GROUP BY position, title ORDER BY position, title`;
        const query = `SELECT position, SUM(score) AS score FROM Achievements WHERE date BETWEEN '${min_date}' AND '${max_date}' GROUP BY position ORDER BY position`;
        var [data, field] = await database.execute(query);
        console.log('\tdata retrieved');
        res.json({"result": "OK", "message": "Data retrieved", "data": data});
    } catch (err) {
        console.log('\tERR: ', err.message);
        res.json({"result": "ERROR", "message": err.message});
    }
});

app.get('/position_compare', authenticateAdmin, async (req, res) => {
    const max_date = req.query.max_date;
    const min_date = req.query.min_date;
    console.log('get position compare data');
    try {
        // const query = `SELECT position, title, SUM(score) AS score FROM Achievements GROUP BY position, title ORDER BY position, title`;
        const query = `SELECT title, SUM(score) AS score FROM Achievements WHERE date BETWEEN '${min_date}' AND '${max_date}' GROUP BY title ORDER BY title`;
        var [data, field] = await database.execute(query);
        console.log('\tdata retrieved');
        res.json({"result": "OK", "message": "Data retrieved", "data": data});
    } catch (err) {
        console.log('\tERR: ', err.message);
        res.json({"result": "ERROR", "message": err.message});
    }
});

app.get('/branch_position_compare', authenticateAdmin, async (req, res) => {
    const max_date = req.query.max_date;
    const min_date = req.query.min_date;
    console.log('get branch position compare data');
    try {
        // const query = `SELECT position, title, SUM(score) AS score FROM Achievements GROUP BY position, title ORDER BY position, title`;
        const query = `SELECT position, title, SUM(score) AS score FROM Achievements WHERE date BETWEEN '${min_date}' AND '${max_date}' GROUP BY position, title ORDER BY position, title`;
        var [data, field] = await database.execute(query);
        console.log('\tdata retrieved');
        res.json({"result": "OK", "message": "Data retrieved", "data": data});
    } catch (err) {
        console.log('\tERR: ', err.message);
        res.json({"result": "ERROR", "message": err.message});
    }
});

app.post('/data/check', authenticateToken, async (req, res) => {
    console.log('check data');
    try {
        const { date, position, title, name } = req.body;
        if (!date || !position || !title || !name) {
            console.log('\tERR: invalid general information');
            res.json({"result": "ERROR", "message": "Incomplete General Information"});
            return;
        }
        const month_date = dayjs(date).format('YYYY-MM-DD');
        const query = `SELECT * FROM Achievements WHERE date='${month_date}' AND position='${position}' AND title='${title}' AND name='${name}'`;
        var [data, filed] = await database.execute(query);
        if (data.length == 0) {
            console.log('\tdata not found');
            res.json({"result": "OK", "message": "Data not found"});
            return;
        } else {
            console.log('\tdata found');
            res.json({"result": "FOUND", "message": "Data found"});
            return;
        }
    } catch (err) {
        console.log('\tERR: ', err.message);
        res.json({"result": "ERROR", "message": err.message});
    }
});

app.post('/data', authenticateToken, async (req, res) => {
    console.log('insert data');
    try {
        const { date, position, title, name } = req.body;
        if (!date || !position || !title || !name) {
            res.json({"result": "ERROR", "message": "Incomplete General Information"});
            return;
        }
        // const month_date = dayjs(date).format('YYYY-MM');
        const get_rule_query = `SELECT * FROM Rules`;
        var [rule, filed] = await database.execute(get_rule_query);
        if (rule.length == 0) {
            console.log('\tERR: rule not found');
            res.json({"result": "ERROR", "message": "The points rules for this month have not been set. Please contact the administrator."});
            return;
        }
        console.log('\trule retrieved');
        const rule_data = rule[0];
        var total_score = 0;
        for (var key in rule_data) {
            if (key == 'date' || key == 'id') {
                continue;
            }
            if (rule_data[key] == null || req.body[key] == undefined) {
                res.json({"result": "ERROR", "message": key + " is not set"});
                return;
            }
            total_score += rule_data[key] * req.body[key];
            
        }
        console.log('\ttotal score calculated ', total_score);
        var query = `INSERT INTO Achievements (date, score, position, title, name) VALUES ('${dayjs(date).format('YYYY-MM-DD')}', '${total_score}', '${position}', '${title}', '${name}')`;
        checkquery = `SELECT * FROM Achievements WHERE date='${dayjs(date).format('YYYY-MM-DD')}' AND position='${position}' AND title='${title}' AND name='${name}'`;
        var [check, filed] = await database.execute(checkquery);
        if (check.length > 0) {
            console.log('\tdata already exists, update data');
            query = `UPDATE Achievements SET score='${total_score}' WHERE date='${date}' AND position='${position}' AND title='${title}' AND name='${name}'`;
        }
        await database.execute(query);

        res.json({"result": "OK", "message": "Data inserted"});
    } catch (err) {
        res.json({"result": "ERROR", "message": err.message});
    }
});

app.get('/user', authenticateToken, async (req, res) => {
    try {
        res.json({"result": "OK", "message": "User data retrieved", "data": {
            "username": req.username,
            "title": req.title,
            "position": req.position
        }});
    } catch (err) {
        res.json({"result": "ERROR", "message": err.message});
    }
});


// Start server
const http = require('http');
const server = http.createServer(app);
server.listen(port, () => {
    console.log(`Server running at port `+port);
});

server.on('error', onError);
server.on('listening', onListening);

function onError(error) {
    if (error.syscall !== 'listen') {
        throw error;
    }
    var bind = typeof port === 'string' ? 'Pipe ' + port : 'Port ' + port;
    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
        default:
            throw error;
    }
}

function onListening() {
    var addr = server.address();
    var bind = typeof addr === 'string' ? 'pipe ' + addr : 'port ' + addr.port;
    console.log('Listening on ' + bind);
}

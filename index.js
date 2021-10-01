const Koa = require("koa");
const bodyParser = require("koa-bodyparser");
const Router = require("koa-router");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = new Koa();
const router = new Router();

// Enmap Imports
const Enmap = require("enmap");
const users = new Enmap({ name: "users" });

const bcrypt = require("bcrypt");

const session = require("koa-session");

const newuser = (username, name = "", plainpw, admin = false) => {
    return new Promise((resp, rejt) => {
        if (users.has(username)) rejt(`User ${username} already exists!`);
        else
            bcrypt.hash(plainpw, 10, (err, password) => {
                if (err) rejt(err);
                resp(
                    users.set(username, {
                        username,
                        name,
                        password,
                        admin,
                        created: Date.now(),
                    })
                );
            });
    });
};

const login = (username, password) => {
    const user = users.get(username);
    if (!user) return new Promise((resp) => resp(false));
    if (!password) return new Promise((resp) => resp(false));
    return bcrypt.compare(password, user.password);
};

app.keys = [process.env.SECRET_KEY];
app.use(session(app));

router.post("/register", async (ctx) => {
    if (!ctx.request.body.username || !ctx.request.body.password) {
        ctx.throw(400, "Missing Username or Password");
    }

    return newuser(
        ctx.request.body.username,
        ctx.request.body.name,
        ctx.request.body.password,
        ctx.request.body.admin
    )
        .then(() => {
            const user = users.get(ctx.request.body.username);

            ctx.session.logged = true;
            ctx.session.username = ctx.request.body.username;
            ctx.session.admin = user.admin;
            ctx.session.name = user.name;

            ctx.session.save();

            ctx.body = `${
                ctx.session.admin ? "Admin" : "User"
            } was registered successfully`;
        })
        .catch((err) => {
            ctx.throw(400, err.message);
        });
});

router.post("/login", async (ctx) => {
    if (!ctx.request.body.username || !ctx.request.body.password) {
        ctx.throw(400, "Missing Username or Password");
    }

    const success = await login(
        ctx.request.body.username,
        ctx.request.body.password
    );

    if (success) {
        const user = users.get(ctx.request.body.username);

        ctx.session.logged = true;
        ctx.session.username = ctx.request.body.username;
        ctx.session.admin = user.admin;
        ctx.session.name = user.name;

        ctx.session.save();
        console.log(`User authenticated: ${user.username}`);

        ctx.redirect("/secret");
    } else {
        console.log("Authentication Failed");
        ctx.throw(403, "Nope. Not allowed, mate.");
    }
});

router.get("/logout", async (ctx) => {
    ctx.session = null;
    ctx.body = "Logged out";
});

router.get("/secret", async (ctx) => {
    if (!ctx.session.logged) ctx.throw(403, "Unauthorized to view this page");
    ctx.body = `${
        ctx.session.admin ? "Admin" : "User"
    } was authorized successfully`;
});

app.use(
    bodyParser({
        multipart: true,
        urlencoded: true,
    })
);

const PORT = process.env.PORT;

router.post("/messages", async (ctx) => {
    console.log(ctx.session);

    if (
        typeof ctx.session === "undefined" ||
        Object.keys(ctx.session).length === 0
    )
        ctx.body = "No Authenticated";

    let from = ctx.request.body.from;
    let to = ctx.request.body.to;
    let message = ctx.request.body.message;

    let writeJson = () => {
        return new Promise((resolve, reject) => {
            if (ctx.session && ctx.session.logged === true) {
                fs.readFile(
                    path.join(__dirname, "/messages.json"),
                    function (err, data) {
                        if (err) {
                            resolve({ code: -1, msg: "New failure" + err });
                            return console.error(err);
                        }

                        let jsonData = data.toString();
                        jsonData = JSON.parse(jsonData);

                        jsonData.push({
                            from: from,
                            to: to,
                            message: message,
                        });

                        let str = JSON.stringify(jsonData);
                        fs.writeFile(
                            path.join(__dirname, "/messages.json"),
                            str,
                            function (err) {
                                if (err) {
                                    resolve({
                                        code: -1,
                                        msg: "New failure" + err,
                                    });
                                }
                                resolve({ code: 0, msg: "New success" });
                            }
                        );
                    }
                );
            } else resolve({ code: -1, msg: "No Auth" });
        });
    };

    ctx.body = await writeJson();
});

router.get("/stats", async (ctx) => {
    let statsJson = () => {
        return new Promise((resolve, reject) => {
            if (ctx.session && ctx.session.logged === true) {
                if (ctx.session.admin === true)
                    fs.readFile(
                        path.join(__dirname, "/messages.json"),
                        function (err, data) {
                            if (err) {
                                resolve({
                                    code: -1,
                                    msg: "Query failed" + err,
                                });
                                return console.error(err);
                            }

                            let jsonData = data.toString();
                            jsonData = JSON.parse(jsonData);

                            responseData = {
                                numberOfCalls: jsonData.length,
                                lastMessage: jsonData[jsonData.length - 1],
                            };
                            resolve({ code: 0, data: responseData });
                        }
                    );
                else resolve({ code: -1, msg: "No permission" });
            } else resolve({ code: -1, msg: "No Auth" });
        });
    };

    if (ctx.session) ctx.body = await statsJson();
});

app.use(router.routes()).use(router.allowedMethods());

app.on("error", (err, ctx) => {
    console.error("server error", err, ctx);
});

app.listen(PORT, () => {
    console.log(`Server listening on port: ${PORT}`);
});

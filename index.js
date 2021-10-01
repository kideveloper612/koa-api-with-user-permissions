const Koa = require("koa");
const bodyParser = require("koa-bodyparser");
const Roles = require("koa-roles");
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
    ctx.body("Logged out");
});

router.get("/secret", async (ctx) => {
    if (!ctx.session.logged) ctx.throw(403, "Unauthorized to view this page");
    ctx.body = `${
        ctx.session.admin ? "Admin" : "User"
    } was authorized successfully`;
});

const user = new Roles({
    async failureHandler(ctx, action) {
        // user fails authorisation
        ctx.status = 403;
        var t = ctx.accepts("json", "html");
        if (t === "json") {
            ctx.body = {
                message:
                    "Access Denied - You don't have permission to: " + action,
            };
        } else if (t === "html") {
            ctx.render("access-denied", { action: action });
        } else {
            ctx.body =
                "Access Denied - You don't have permission to: " + action;
        }
    },
});

app.use(user.middleware());
app.use(
    bodyParser({
        multipart: true,
        urlencoded: true,
    })
);

const PORT = process.env.PORT;

// anonymous users can only access the messages endpoint
user.use(async (ctx, action) => {
    return ctx.user || action === "access messages";
});

//admin users can access all endpoints
user.use((ctx, action) => {
    if (ctx.user.role === "admin") {
        return true;
    }
});

router.post("/messages", user.can("access messages"), async (ctx) => {
    let from = ctx.request.body.from;
    let to = ctx.request.body.to;
    let message = ctx.request.body.message;

    console.log(ctx.request.body);

    let writeJson = () => {
        return new Promise((resolve, reject) => {
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
                                resolve({ code: -1, msg: "New failure" + err });
                            }
                            resolve({ code: 0, msg: "New success" });
                        }
                    );
                }
            );
        });
    };

    ctx.body = await writeJson();
});

router.get("/stats", user.can("admin"), async (ctx) => {
    let statsJson = () => {
        return new Promise((resolve, reject) => {
            fs.readFile(
                path.join(__dirname, "/messages.json"),
                function (err, data) {
                    if (err) {
                        resolve({ code: -1, msg: "Query failed" + err });
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
        });
    };

    ctx.body = await statsJson();
});

// router.use("/", deploy.routes(), deploy.allowedMethods());
app.use(router.routes()).use(router.allowedMethods());

app.on("error", (err, ctx) => {
    console.error("server error", err, ctx);
});

app.listen(PORT, () => {
    console.log(`Server listening on port: ${PORT}`);
});

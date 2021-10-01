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

// Bcrypt's hashing system
const bcrypt = require("bcrypt");

// The default "sessions" support.
const session = require("koa-session");

const newuser = (username, name, plainpw, admin = false) => {
    if (users.has(username))
        return new Promise((resp) => resp(`User ${username} already exists!`));

    return new Promise((resp) => {
        resp(
            bcrypt.hash(plainpw, 10, (err, password) => {
                if (err) throw err;
                users.set(username, {
                    username,
                    name,
                    password,
                    admin,
                    created: Date.now(),
                });
            })
        );
    });
};

const login = (username, password) => {
    const user = this.users.get(username);
    if (!user) return new Promise((resp) => resp(false));
    if (!password) return new Promise((resp) => resp(false));
    return bcrypt.compare(password, user.password);
};

app.keys = [process.env.SECRET_KEY];
app.use(session(app));

router.post("/register", async (ctx) => {
    // Fail if there is no username and password.
    // This relies on koa-bodyparser
    if (!ctx.request.body.username || !ctx.request.body.password) {
        ctx.throw(400, "Missing Username or Password");
    }
    // Use our login function to verify the username/password is correct
    const success = await newuser(
        ctx.request.body.username,
        ctx.request.body.name,
        ctx.request.body.password,
        ctx.request.body.admin
    );

    if (success) {
        // get the user's information
        const user = users.get(ctx.request.body.username);
        // Set all our session parameters:
        ctx.session.logged = true;
        ctx.session.username = ctx.request.body.username;
        ctx.session.admin = user.admin;
        ctx.session.name = user.name;
        // Save the session itself. This sets the cookie in the browser,
        // as well as save into the sessions in memory.
        ctx.session.save();
        console.log(`User authenticated: ${user.username}`);
        // Once logged in, redirect to the secret page.
        ctx.redirect("/secret");
    } else {
        console.log("Authentication Failed");
        // Throw if the above login returns false.
        ctx.throw(403, "Nope. Not allowed, mate.");
    }
});

router.post("/login", async (ctx) => {
    // Fail if there is no username and password.
    // This relies on koa-bodyparser
    if (!ctx.request.body.username || !ctx.request.body.password) {
        ctx.throw(400, "Missing Username or Password");
    }
    // Use our login function to verify the username/password is correct
    const success = await login(
        ctx.request.body.username,
        ctx.request.body.password
    );
    if (success) {
        // get the user's information
        const user = users.get(ctx.request.body.username);
        // Set all our session parameters:
        ctx.session.logged = true;
        ctx.session.username = ctx.request.body.username;
        ctx.session.admin = user.admin;
        ctx.session.name = user.name;
        // Save the session itself. This sets the cookie in the browser,
        // as well as save into the sessions in memory.
        ctx.session.save();
        console.log(`User authenticated: ${user.username}`);
        // Once logged in, redirect to the secret page.
        ctx.redirect("/secret");
    } else {
        console.log("Authentication Failed");
        // Throw if the above login returns false.
        ctx.throw(403, "Nope. Not allowed, mate.");
    }
});

router.get("/logout", async (ctx) => {
    ctx.session = null;
    ctx.redirect("/");
});

router.get("/secret", async (ctx) => {
    if (!ctx.session.logged) ctx.throw(403, "Unauthorized to view this page");
    await ctx.render("secret");
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

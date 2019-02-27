// -*- coding: utf-8 -*-

// Authenticate LWA token to allow access through nginx
// Returns 200 for allowed, 401 for not allowed

'use strict';

const http = require('http');
const https = require('https');
var Promise = require('promise');
var bodyJson = require("body/json");

// Cookie cache
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const adapter = new FileSync('cookiecache.json');
const db = low(adapter);

// Load list of allowed email addresses. Should contain array of strings under the "addresses" property.
const VALID_EMAILS = require('./emails.json');

// Amazon parameters
const LWA_HOST = "api.amazon.com";


/////// ENTRY POINT ////////

// Setup cache
db.defaults({ cookies: []}).write();

// Setup HTTP server
const server = http.createServer(handleHttpRequest);
const port = 2999;

server.listen(port, (err) => {
    if (err) 
    {
        return console.log("Error creating server", err);
    }

    console.log("lwa_auth running on port", port);
});


async function handleHttpRequest(request, response)
{
    console.log("Request", request.headers["x-original-uri"]);

    // Validate request
    var status = 401;
    var statusMessage = "Unauthorized";
    var message = null;             // The JSON body of the message that was sent to us

    try
    {
        var token = request.headers["authorization"];
        if (token == null) throw ("No authorization header");
        
        await validateToken(token);       // Will throw if not valid or some other error

        status = 200;
        statusMessage = "OK";
    } 
    catch (err)
    {
        console.log("Error or unauthorized", err);
    }

    console.log("Returning status", status, statusMessage);
    response.statusCode = status;
    response.status = statusMessage;
    response.end();

    // Clean up cookie cache
    // Older than 30 minutes
    var thirtyAgo = new Date(new Date().getTime() - 30 * 60 * 1000);
    db.get("cookies").remove(record => new Date(record.date) < thirtyAgo).write();
}

async function validateToken(token)
{
    var userEmail = "";
    var newToken = false;

    // Cookie in cache?
    var foundInCache = db.get("cookies").find({ token: token }).value();
    if (foundInCache)
    {
        userEmail = foundInCache.email;
        console.log("Found token in cache, email:", userEmail);
    }
    else
    {
        // Not in cache, ask Amazon
        var lwaResponse = await lwaHttpsGetRequest(token);
        console.log("LWA response", lwaResponse);

        userEmail = lwaResponse.email;
        newToken = true;
    }

    // Email check in provided list
    var mailFound = VALID_EMAILS.addresses.find(email => { return email == userEmail; });
    if (! mailFound) throw("Unknown user " + userEmail);

    // If we get here, it is a valid token
    // See if we need to store it in the cache
    if (newToken)
    {
        db.get("cookies").push({token: token, email: userEmail, date: new Date()}).write();
    }
}

async function lwaHttpsGetRequest(token)
{
    console.log("Executing HTTP get to LWA");

    return new Promise((resolve, reject) => {
        var options = {
            host: LWA_HOST,
            path: "/user/profile",
            headers:
            {
                "Authorization": token,
                "Accept": "application/json"
            }
        };

        https.get(options, (res) => {
            console.log("Amazon responds ", res.statusCode);

            if (200 == res.statusCode) 
            {
                bodyJson(res, function (err, body) {
                   if (err) reject(err);
                   else resolve(body);
                });
            }
            else reject(res.statusCode);
        });

    });
}


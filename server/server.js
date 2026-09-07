const http = require("http");

const PORT = process.env.PORT || 3000;

const server = http.createServer((req, res) => {
    res.writeHead(200, {
        "Content-Type": "application/json"
    });

    res.end(JSON.stringify({
        name: "HOSHINO",
        version: "0.1.0",
        status: "online",
        message: "Welcome to HOSHINO!"
    }));
});

server.listen(PORT, () => {
    console.log(`HOSHINO server is running on port ${PORT}`);
});

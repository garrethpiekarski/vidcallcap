var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var MongoClient = require('mongodb').MongoClient;

var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
  extended: true
}));
app.use(bodyParser.json() );       // to support JSON-encoded bodies

// app.use(app.json());       // to support JSON-encoded bodies
// app.use(app.urlencoded()); // to support URL-encoded bodies

app.get('/', function(req, res) {
    res.sendFile(__dirname + '/index.html');
});

app.get('/fans', function(req, res) {
    res.setHeader('Content-Type', 'application/json');
    MongoClient.connect("mongodb://localhost:27017/fans", function(err, db) {
        db.collection('fanslist', function(err, collection) {
            collection.find().toArray(function(err, items) {
                if (err)
                    throw err;
                res.send(items);
            });
        });
    });
});

app.post('/fan', function(req, res) {
    var pData = JSON.parse(req.body.entry);
    MongoClient.connect("mongodb://localhost:27017/fans", function(err, db) {
        db.collection('fanslist').insertOne(pData, function(err, result) {
            if (err) { throw err; }
            console.log("Inserted a document into the fans collection.");
        });
    });
});

io.on('connection', function(socket) {
    console.log('a user connected');
});

http.listen(3000, function() {
    console.log('listening on *:3000');
});

var fetch = require('node-fetch');
var pcap = require('pcap'),
    pcap_session = pcap.createSession('', 'udp'),
    filterList = [
        '192.168.',
        '173.194.68.189',
        '254.128',
        '172.217.7.164',
        '172.217.7.164',
        '216.58.219.206',
        '172.217.0.35'
    ],
    storedList = [],
    latestPackets = [],
    totalRequests = 0;

var mode = function(array) {
    if (array.length === 0)
        return null;
    var modeMap = {};
    var maxEl = array[0],
        maxCount = 1;
    for (var i = 0; i < array.length; i++) {
        var el = array[i];
        if (modeMap[el] === null)
            modeMap[el] = 1;
        else
            modeMap[el]++;
        if (modeMap[el] > maxCount) {
            maxEl = el;
            maxCount = modeMap[el];
        }
    }
    return maxEl;
};

setInterval(getPacketModeAndClear, 500);

function getPacketModeAndClear() {
    //check if there are any packets
    if (latestPackets.length < 1) {
        return;
    }

    //get the mode of the packets
    var packetMode = mode(latestPackets);

    console.log(packetMode);

    //get the geo information of the packet
    // check if ip matches anything in filter list
    let filtered = filterList.find(function(listItem) {
        return packetMode.match(listItem);
    });
    // log IP if not filtered
    if (typeof filtered === 'undefined') {
        let stored = storedList.find(function(listItem) {
            return packetMode.match(listItem.ip);
        });
        if (typeof stored === 'undefined') {
            console.log('not in list: ');
            fetch('http://freegeoip.net/json/' + packetMode).then(function(response) {
                if (response.status !== 200) {
                    console.log('Looks like there was a problem. Status Code: ' + response.status);
                    return;
                }

                // Examine the text in the response
                response.json().then(function(data) {
                    console.log(data);
                    storedList.push(data);
                    io.emit('address', JSON.stringify(data));
                });
            }).catch(function(err) {
                console.log('Fetch Error :-S', err);
            });
            totalRequests += 1;
        } else {
            console.log('in list:');
            console.log(stored);
            io.emit('address', JSON.stringify(stored));
        }

    }
    console.log(`Total requests: ${totalRequests}`);

    //clear list
    latestPackets = [];
}

pcap_session.on('packet', function(raw_packet) {

    // find packet source IP
    var packet = pcap.decode.packet(raw_packet),
        sourceIp = packet.payload.payload.saddr.addr.join('.');

    latestPackets.push(sourceIp);

});
